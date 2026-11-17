# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Code indexer: deterministic code index for deep scan.

Builds a structural index of the target codebase using tree-sitter:
- Function/method inventory with location and body (FR-020)
- Call graph: which function calls which (FR-021)
- Query interface: get-function-body, get-callers, get-callees, find-symbol (FR-022)
- Incremental on re-run: only changed files re-parsed (FR-026)

The Indexer uses a deterministic parser (tree-sitter) as required by FR-020.
LLM extraction is NOT used for indexing — the parser is the sole source.

Constitution alignment:
  XI. Persist Atomically — index writes are atomic via temp-then-rename
"""

import hashlib
import json
import logging
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from tree_sitter import Language, Parser

logger = logging.getLogger(__name__)

# --- Language registry ---

# Map file extensions to tree-sitter language modules
_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sc": "scala",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "c_sharp",
    ".php": "php",
    ".swift": "swift",
    ".sh": "bash",
    ".bash": "bash",
}

# Tree-sitter node types that represent function definitions per language
_FUNCTION_NODE_TYPES: Dict[str, Set[str]] = {
    "python": {"function_definition", "decorated_definition"},
    "java": {"method_declaration", "constructor_declaration"},
    "javascript": {"function_declaration", "method_definition", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "arrow_function"},
    "go": {"function_declaration", "method_declaration"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "ruby": {"method", "singleton_method"},
    "rust": {"function_item"},
    "scala": {"function_definition", "class_definition", "object_definition"},
    "kotlin": {"function_declaration"},
    "c_sharp": {"method_declaration", "constructor_declaration"},
    "php": {"function_definition", "method_declaration"},
    "swift": {"function_declaration"},
    "bash": {"function_definition"},
}

# Node types that represent function/method calls
_CALL_NODE_TYPES: Dict[str, Set[str]] = {
    "python": {"call"},
    "java": {"method_invocation"},
    "javascript": {"call_expression"},
    "typescript": {"call_expression"},
    "go": {"call_expression"},
    "c": {"call_expression"},
    "cpp": {"call_expression"},
    "ruby": {"method_call", "call"},
    "rust": {"call_expression"},
    "scala": {"call_expression"},
    "kotlin": {"call_expression"},
    "c_sharp": {"invocation_expression"},
    "php": {"function_call_expression"},
    "swift": {"call_expression"},
    "bash": {"command"},
}


def _load_language(lang_name: str) -> Optional[Language]:
    """Load a tree-sitter language by name."""
    try:
        module = __import__(f"tree_sitter_{lang_name}")
        # PHP uses language_php() instead of language()
        loader = getattr(module, f"language_{lang_name}", None) or getattr(module, "language")
        return Language(loader())
    except (ImportError, AttributeError) as e:
        logger.debug("Language %s not available: %s", lang_name, e)
        return None


def _get_language_for_file(file_path: str) -> Optional[str]:
    """Get the language name for a file based on extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return _LANGUAGE_MAP.get(ext)


# --- Data classes ---

class FunctionInfo:
    """Information about a function/method in the codebase."""

    def __init__(self, name: str, file_path: str, start_line: int, end_line: int,
                 body: str, language: str, class_name: Optional[str] = None):
        self.name = name
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.body = body
        self.language = language
        self.class_name = class_name

    @property
    def qualified_name(self) -> str:
        if self.class_name:
            return f"{self.class_name}.{self.name}"
        return self.name

    @property
    def key(self) -> str:
        return f"{self.file_path}:{self.qualified_name}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "body": self.body,
            "language": self.language,
            "class_name": self.class_name,
        }


# --- Parser ---

class TreeSitterParser:
    """Tree-sitter based parser for extracting functions and call sites."""

    def __init__(self):
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, Language] = {}

    def _get_parser(self, lang_name: str) -> Optional[Parser]:
        """Get or create a parser for the given language."""
        if lang_name not in self._parsers:
            language = _load_language(lang_name)
            if language is None:
                return None
            parser = Parser(language)
            self._parsers[lang_name] = parser
            self._languages[lang_name] = language
        return self._parsers.get(lang_name)

    def parse_file(self, file_path: str, source: Optional[bytes] = None) -> Tuple[List[FunctionInfo], List[Tuple[str, str]]]:
        """
        Parse a file and extract functions and call relationships.

        Returns:
            (functions, calls) where calls is a list of (caller_key, callee_name) tuples
        """
        lang_name = _get_language_for_file(file_path)
        if not lang_name:
            return [], []

        parser = self._get_parser(lang_name)
        if not parser:
            return [], []

        if source is None:
            try:
                with open(file_path, "rb") as f:
                    source = f.read()
            except (OSError, IOError) as e:
                logger.warning("Cannot read %s: %s", file_path, e)
                return [], []

        tree = parser.parse(source)
        functions = self._extract_functions(tree.root_node, file_path, source, lang_name)
        calls = self._extract_calls(tree.root_node, file_path, source, lang_name, functions)
        return functions, calls

    def _extract_functions(self, root_node, file_path: str, source: bytes,
                           lang_name: str) -> List[FunctionInfo]:
        """Extract all function/method definitions from the parse tree."""
        functions: List[FunctionInfo] = []
        func_types = _FUNCTION_NODE_TYPES.get(lang_name, set())

        def visit(node, class_name=None):
            # Track class context
            current_class = class_name
            if node.type in ("class_definition", "class_declaration",
                             "class_body", "interface_declaration"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    current_class = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")

            if node.type in func_types:
                func_info = self._node_to_function(node, file_path, source, lang_name, current_class)
                if func_info:
                    functions.append(func_info)

            # Handle Python decorated_definition: the function is inside it
            if node.type == "decorated_definition" and lang_name == "python":
                for child in node.children:
                    if child.type == "function_definition":
                        func_info = self._node_to_function(child, file_path, source, lang_name, current_class)
                        if func_info:
                            functions.append(func_info)
                return  # Don't recurse into decorated_definition children again

            for child in node.children:
                visit(child, current_class)

        visit(root_node)
        return functions

    def _node_to_function(self, node, file_path: str, source: bytes,
                          lang_name: str, class_name: Optional[str]) -> Optional[FunctionInfo]:
        """Convert a tree-sitter node to FunctionInfo."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None

        name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        body = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1

        return FunctionInfo(
            name=name,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            body=body,
            language=lang_name,
            class_name=class_name,
        )

    def _extract_calls(self, root_node, file_path: str, source: bytes,
                       lang_name: str, functions: List[FunctionInfo]) -> List[Tuple[str, str]]:
        """Extract call relationships: which function calls which."""
        call_types = _CALL_NODE_TYPES.get(lang_name, set())
        calls: List[Tuple[str, str]] = []

        # Build a line-range to function-key map
        func_ranges: List[Tuple[int, int, str]] = []
        for func in functions:
            func_ranges.append((func.start_line, func.end_line, func.key))

        def find_containing_function(line: int) -> Optional[str]:
            for start, end, key in func_ranges:
                if start <= line <= end:
                    return key
            return None

        def visit(node):
            if node.type in call_types:
                callee_name = self._extract_callee_name(node, source, lang_name)
                if callee_name:
                    call_line = node.start_point[0] + 1
                    caller_key = find_containing_function(call_line)
                    if caller_key:
                        calls.append((caller_key, callee_name))

            for child in node.children:
                visit(child)

        visit(root_node)
        return calls

    def _extract_callee_name(self, call_node, source: bytes, lang_name: str) -> Optional[str]:
        """Extract the name being called from a call expression node."""
        if lang_name == "python":
            func_node = call_node.child_by_field_name("function")
            if func_node:
                # Handle obj.method() — extract just the method name
                if func_node.type == "attribute":
                    attr = func_node.child_by_field_name("attribute")
                    if attr:
                        return source[attr.start_byte:attr.end_byte].decode("utf-8", errors="replace")
                return source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
        elif lang_name == "java":
            name_node = call_node.child_by_field_name("name")
            if name_node:
                return source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        else:
            # Generic: try 'function' field first, then 'name'
            for field in ("function", "name"):
                child = call_node.child_by_field_name(field)
                if child:
                    if child.type in ("member_expression", "attribute", "field_expression"):
                        prop = child.child_by_field_name("property") or child.child_by_field_name("attribute") or child.child_by_field_name("field")
                        if prop:
                            return source[prop.start_byte:prop.end_byte].decode("utf-8", errors="replace")
                    return source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        return None


# --- Code Index ---

class CodeIndex:
    """
    Queryable code index implementing FR-022.

    Provides: get_function_body, get_callers, get_callees,
    find_symbol, full_text_search, list_functions_in_file.
    """

    def __init__(self):
        self._functions: Dict[str, FunctionInfo] = {}  # key → FunctionInfo
        self._by_name: Dict[str, List[str]] = defaultdict(list)  # name → [keys]
        self._by_file: Dict[str, List[str]] = defaultdict(list)  # file → [keys]
        self._callees: Dict[str, Set[str]] = defaultdict(set)  # caller_key → {callee_names}
        self._callers: Dict[str, Set[str]] = defaultdict(set)  # callee_name → {caller_keys}
        self._file_hashes: Dict[str, str] = {}  # file_path → content hash
        self._parser = TreeSitterParser()
        self._queryable = False

    @property
    def is_queryable(self) -> bool:
        """Whether the index has been built and is ready for queries (FR-024)."""
        return self._queryable

    def build(self, target_path: str, include_patterns: Optional[List[str]] = None,
              exclude_patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Build the index from a target directory or file (FR-020, FR-021).

        Respects configured scope via include/exclude patterns (FR-027).
        Degrades gracefully on unparseable files (FR-028).
        """
        stats = {"files_parsed": 0, "files_skipped": 0, "functions_found": 0,
                 "calls_found": 0, "errors": 0}

        if os.path.isfile(target_path):
            files = [target_path]
        else:
            files = self._collect_files(target_path, include_patterns, exclude_patterns)

        for file_path in files:
            try:
                content_hash = self._hash_file(file_path)

                # Incremental: skip unchanged files (FR-026)
                if file_path in self._file_hashes and self._file_hashes[file_path] == content_hash:
                    stats["files_skipped"] += 1
                    continue

                functions, calls = self._parser.parse_file(file_path)

                if not functions and _get_language_for_file(file_path):
                    stats["files_skipped"] += 1
                    continue

                # Remove old entries for this file before adding new ones
                self._remove_file(file_path)

                for func in functions:
                    self._functions[func.key] = func
                    self._by_name[func.name].append(func.key)
                    self._by_file[file_path].append(func.key)

                for caller_key, callee_name in calls:
                    self._callees[caller_key].add(callee_name)
                    self._callers[callee_name].add(caller_key)

                self._file_hashes[file_path] = content_hash
                stats["files_parsed"] += 1
                stats["functions_found"] += len(functions)
                stats["calls_found"] += len(calls)

            except Exception as e:
                logger.warning("Failed to parse %s: %s", file_path, e)
                stats["errors"] += 1

        self._queryable = stats["functions_found"] > 0 or len(self._functions) > 0
        logger.info("Index built: %d files, %d functions, %d calls",
                     stats["files_parsed"], stats["functions_found"], stats["calls_found"])
        return stats

    def _remove_file(self, file_path: str):
        """Remove all entries for a file (for re-indexing)."""
        old_keys = self._by_file.pop(file_path, [])
        for key in old_keys:
            self._functions.pop(key, None)
            # Clean up name index
            func_name = key.split(":")[-1].split(".")[-1]
            if func_name in self._by_name:
                self._by_name[func_name] = [k for k in self._by_name[func_name] if k != key]
            # Clean up call graph
            self._callees.pop(key, None)
            for callee, callers in self._callers.items():
                callers.discard(key)

    def _collect_files(self, directory: str,
                       include_patterns: Optional[List[str]],
                       exclude_patterns: Optional[List[str]]) -> List[str]:
        """Collect files to index, respecting scope rules (FR-027)."""
        files: List[str] = []
        exclude = set(exclude_patterns or [])
        # Default excludes
        default_excludes = {".git", "node_modules", "__pycache__", ".venv", "venv",
                           "vendor", "target", "build", "dist", ".tox", ".eggs"}
        exclude.update(default_excludes)

        for root, dirs, filenames in os.walk(directory):
            # Filter directories
            dirs[:] = [d for d in dirs if d not in exclude
                       and not any(d.startswith(p) for p in exclude if not p.startswith("."))]

            for filename in filenames:
                file_path = os.path.join(root, filename)
                lang = _get_language_for_file(file_path)
                if lang is None:
                    continue

                if include_patterns:
                    if not any(file_path.endswith(p.lstrip("*")) for p in include_patterns):
                        continue

                files.append(file_path)

        return sorted(files)

    @staticmethod
    def _hash_file(file_path: str) -> str:
        """Compute content hash for incremental indexing."""
        h = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Query interface (FR-022) ---

    def get_function_body(self, file_path: str, function_name: str) -> Optional[str]:
        """Get the body of a specific function."""
        key = f"{file_path}:{function_name}"
        func = self._functions.get(key)
        if func:
            return func.body
        # Try qualified name lookup
        for k, f in self._functions.items():
            if k.endswith(f":{function_name}") and f.file_path == file_path:
                return f.body
        return None

    def get_callers(self, function_name: str) -> List[Dict[str, Any]]:
        """Get all functions that call the given function (FR-021)."""
        caller_keys = self._callers.get(function_name, set())
        result = []
        for key in caller_keys:
            func = self._functions.get(key)
            if func:
                result.append(func.to_dict())
        return result

    def get_callees(self, file_path: str, function_name: str) -> List[str]:
        """Get all functions called by the given function (FR-021)."""
        key = f"{file_path}:{function_name}"
        callees = self._callees.get(key, set())
        if not callees:
            for k in self._functions:
                if k.endswith(f":{function_name}") and self._functions[k].file_path == file_path:
                    callees = self._callees.get(k, set())
                    break
        return sorted(callees)

    def find_symbol(self, name: str) -> List[Dict[str, Any]]:
        """Find all functions/methods with the given name (FR-022)."""
        keys = self._by_name.get(name, [])
        return [self._functions[k].to_dict() for k in keys if k in self._functions]

    def list_functions_in_file(self, file_path: str) -> List[Dict[str, Any]]:
        """List all functions defined in a file (FR-020)."""
        keys = self._by_file.get(file_path, [])
        return [self._functions[k].to_dict() for k in keys if k in self._functions]

    def full_text_search(self, query: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search function bodies for a text pattern (FR-022)."""
        results = []
        if not case_sensitive:
            query = query.lower()
        for func in self._functions.values():
            body = func.body if case_sensitive else func.body.lower()
            if query in body:
                results.append(func.to_dict())
        return results

    def get_all_functions(self) -> List[Dict[str, Any]]:
        """Get all indexed functions."""
        return [f.to_dict() for f in self._functions.values()]

    # --- Persistence ---

    def save(self, path: str):
        """
        Save the index to a JSON file (FR-025).

        Uses write-to-temp-then-rename for atomic persistence (Constitution XI).
        """
        data = {
            "functions": {k: v.to_dict() for k, v in self._functions.items()},
            "callees": {k: sorted(v) for k, v in self._callees.items()},
            "callers": {k: sorted(v) for k, v in self._callers.items()},
            "file_hashes": self._file_hashes,
        }
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
        logger.info("Index saved to %s", path)

    def load(self, path: str) -> bool:
        """Load a previously saved index."""
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r") as f:
                data = json.load(f)

            self._functions = {}
            for key, fdict in data.get("functions", {}).items():
                self._functions[key] = FunctionInfo(**{k: v for k, v in fdict.items()
                                                       if k != "qualified_name"})
                self._by_name[fdict["name"]].append(key)
                self._by_file[fdict["file_path"]].append(key)

            self._callees = {k: set(v) for k, v in data.get("callees", {}).items()}
            self._callers = {k: set(v) for k, v in data.get("callers", {}).items()}
            self._file_hashes = data.get("file_hashes", {})
            self._queryable = len(self._functions) > 0

            logger.info("Index loaded from %s: %d functions", path, len(self._functions))
            return True
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.error("Failed to load index from %s: %s", path, e)
            return False
