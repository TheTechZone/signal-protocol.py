import importlib
import pkgutil
import sys
import inspect
import signal_protocol
import ast
import re
import logging
from pathlib import Path
import difflib


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    )

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def merge_multiline_strings(text1: str, text2: str) -> str:
    # Split the strings into lists of lines
    lines1 = text1.splitlines(keepends=True)
    lines2 = text2.splitlines(keepends=True)

    # Use difflib to compare the lines
    differ = difflib.Differ()
    diff = differ.compare(lines1, lines2)

    # Initialize variables to track the state of the merge
    merged_lines = []
    conflict_started = False
    delim_added = False

    for line in diff:
        # Check if the line is part of a conflict
        if line.startswith("- "):
            if not conflict_started:
                merged_lines.append("\n<<<<<<<")
                conflict_started = True
                delim_added = False

            merged_lines.append(line[2:])
        elif line.startswith("+ "):
            if not conflict_started:
                merged_lines.append("\n<<<<<<<")
                conflict_started = True
                delim_added = False
            elif not delim_added:
                merged_lines.append("=======")
                delim_added = True

            merged_lines.append(line[2:])
        elif line.startswith(" "):
            # If a conflict has started, close it before adding the common line
            if conflict_started:
                if not delim_added:
                    merged_lines.append("=======")
                    delim_added = True
                merged_lines.append(line[2:])
                merged_lines.append("\n>>>>>>>")
                conflict_started = False
            else:
                merged_lines.append(line[2:])
    # Close any open conflict
    if conflict_started:
        if not delim_added:
            merged_lines.append("=======")
        merged_lines.append(">>>>>>>")

    # Join the merged lines back into a single string
    merged_string = "\n".join(merged_lines) + "\n"
    return merged_string


logger = logging.getLogger("stub_fixer")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)
logger.propagate = False


def find_abs_modules(module):
    path_list = []
    spec_list = []
    for importer, modname, ispkg in pkgutil.walk_packages(module.__path__):
        import_path = f"{module.__name__}.{modname}"
        if ispkg:
            spec = pkgutil._get_spec(importer, modname)
            importlib._bootstrap._load(spec)
            spec_list.append(spec)
        else:
            path_list.append(import_path)
    for spec in spec_list:
        del sys.modules[spec.name]
    return path_list


def list_module_objects(module):
    # Get all members of the module
    members = dir(module)
    # Filter out special methods and attributes
    objects = [member for member in members if not member.startswith("__")]
    return objects


def list_module_functions_and_classes(module):
    # Get all members of the module
    members = inspect.getmembers(module)
    # Filter out functions and classes
    predicate = (
        lambda x: inspect.isfunction(x)
        or inspect.isbuiltin(x)
        or inspect.ismethod(x)
        or inspect.isclass(x)
    )

    objects = [member for member in members if predicate(member[1])]

    all_objects = objects[:]
    logging.debug(f"Found {len(objects)} in {module}")
    # For each class, list its methods excluding inherited ones but including overridden ones
    for obj in objects:
        class_objects = []
        if inspect.isclass(obj[1]):
            # Get the class's dictionary of attributes
            class_dict = obj[1].__dict__
            # Get the base class's dictionary of attributes
            base_class_dict = obj[1].__bases__[0].__dict__ if obj[1].__bases__ else {}
            extra_excludes = ["str", "__module__", "__int__", "__weakref__"]
            # Filter out inherited methods but include overridden ones
            methods = [
                method
                for method in class_dict
                if method
                not in (
                    base_class_dict or class_dict[method] != base_class_dict.get(method)
                )
                and method not in extra_excludes
            ]

            logger.debug(
                f"Methods of {obj[0]} (excluding inherited but including overridden):"
            )
            for method in methods:
                method_obj = getattr(obj[1], method)
                doc = inspect.getdoc(method_obj)
                logger.debug(f"\t{obj[0]}.{method}: {doc}")
                class_objects.append((f"{obj[0]}.{method}", method_obj))
            all_objects.extend(class_objects)

    return all_objects


def get_data_from_package():
    find_abs_modules(signal_protocol)
    excludes = ["signal_protocol", "signal_protocol.signal_protocol"]
    modules = [
        mod
        for mod in sys.modules.items()
        if mod[0].startswith("signal_protocol") and mod[0] not in excludes
    ]

    data = []
    for k, v in modules:
        obj = list_module_objects(v)
        tokens = list_module_functions_and_classes(v)
        data.append((k, obj, tokens))
    return data


STUB_FOLDER = Path("signal_protocol").resolve()


def stubfile_exists(module_name, stub_folder=STUB_FOLDER):
    return (STUB_FOLDER / f"{module_name}.pyi").exists()


def create_new_docs(curr_doc, docs, symbol):
    no_space_1 = re.sub(r"\s+", " ", curr_doc)
    no_space_2 = re.sub(r"\s+", " ", docs)
    if len(docs) == 0 or no_space_1 == no_space_2 or no_space_2 in no_space_1:
        return  # nothing to do here
    elif len(curr_doc) == 0:
        return docs
    else:
        # we have two diffrent docs... merging
        # new_docs = f"""<<<<<<<
        # {curr_doc}
        # =======x
        # {docs}
        # >>>>>>>
        # """
        new_docs = merge_multiline_strings(curr_doc, docs)
        logger.warning(f"Got conflicting docs for symbol {symbol}. MERGING...")
        return new_docs


all_symbols = {}


def inspect_pyi(file_path, docs_dict):
    with open(file_path, "r") as file:
        tree = ast.parse(file.read())

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            curr_doc = ast.get_docstring(node)
            if curr_doc is None:
                curr_doc = ""

            parent = node.parent.name + "." if hasattr(node, "parent") else ""

            key = "".join([parent, node.name]) if len(parent) > 0 else node.name
            docs = docs_dict.get(key, "")
            docs_dict.pop(key, None)
            all_symbols.pop(key, None)

            docstring_node = None
            new_docs = create_new_docs(curr_doc, docs, key)
            if new_docs is None:
                continue
            docstring_node = ast.Expr(value=ast.Constant(new_docs))

            if isinstance(node.body[0].value, ast.Constant):
                node.body = node.body[1:]
            # Insert the new docstring node at the beginning of the function body
            node.body.insert(0, docstring_node)

        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, ast.FunctionDef):
                    child.parent = node
            curr_doc = ast.get_docstring(node)
            if curr_doc is None:
                curr_doc = ""

            docs = docs_dict.get(node.name, "")
            docs_dict.pop(node.name, None)
            all_symbols.pop(node.name, None)

            new_docs = create_new_docs(curr_doc, docs, node.name)
            if new_docs is None:
                continue
            docstring_node = ast.Expr(value=ast.Constant(new_docs))

            if isinstance(node.body[0].value, ast.Constant):
                node.body = node.body[1:]
            # Insert the new docstring node at the beginning of the function body
            node.body.insert(0, docstring_node)
    return tree


def create_dummy(symbol_dict):
    import ast
    import astor

    # Initialize an empty list to hold the AST nodes
    ast_nodes = []
    tag = ast.Expr(
        value=ast.Constant("[AUTOGENERATED] -- TODO: adapt (if needed) and remove me")
    )

    # Function to create a class AST node
    def create_class_ast(class_name):
        class_def = ast.ClassDef(
            name=class_name, bases=[], keywords=[], body=[], decorator_list=[]
        )
        class_def.body.append(tag)
        class_def.body.append(ast.Expr(value=ast.Constant("...")))
        return class_def

    # Function to create a function AST node
    def create_function_ast(function_name):
        function_def = ast.FunctionDef(
            name=function_name,
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=[],
            decorator_list=[],
            returns=None,
        )
        function_def.body.append(tag)
        function_def.body.append(ast.Expr(value=ast.Constant("...")))
        return function_def

    # Function to create a method AST node
    def create_method_ast(method_name):
        function_def = ast.FunctionDef(
            name=method_name,
            args=ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg="self", annotation=None, type_comment=None)],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=[],
            decorator_list=[],
            returns=None,
        )
        function_def.body.append(tag)
        function_def.body.append(ast.Expr(value=ast.Constant("...")))
        return function_def

    # Iterate over the dictionary to create AST nodes
    for symbol, type_ in symbol_dict.items():
        if type_ == "class":
            ast_nodes.append(create_class_ast(symbol))
        elif type_ == "function":
            ast_nodes.append(create_function_ast(symbol))
        elif type_ == "method":
            class_name, method_name = symbol.split(".")
            # Assuming the class already exists in the ast_nodes list
            for node in ast_nodes:
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    node.body.append(create_method_ast(method_name))
                    break

    # Create a module AST node to hold all the other nodes
    module_ast = ast.Module(body=ast_nodes)

    # Convert the AST to source code (and fix the empty bodies)
    source_code = astor.to_source(module_ast).replace('"""..."""', "...")

    # Output the generated source code
    return source_code


if __name__ == "__main__":

    logger.info("started_script")
    data = get_data_from_package()
    logger.info(f"found {len(data)} modules")

    for item in data:
        module, _, symbols = item
        module = module.removeprefix("signal_protocol.")

        stub_fp = (STUB_FOLDER / f"{module}.pyi").resolve()

        if not stubfile_exists(module):
            logger.warning(
                f"The stubfile {module}.pyi does not exists, consider creating it. Creating dummy..."
            )

            syms = {}
            for sym in symbols:
                sname, obj = sym
                stype = str(type(obj))
                if "." in sname and "method" in stype:
                    stype = "method"
                elif "type" in stype:
                    stype = "class"
                else:
                    stype = "function"
                syms[sname] = stype

            dummy_code = create_dummy(syms)

            with stub_fp.open("w") as f:
                f.write(dummy_code)
            continue

        all_symbols = {}
        # build dict of symbols with docstrings
        docstring_lookup = {}

        for sym in symbols:
            sname, obj = sym
            doc = inspect.getdoc(obj)
            all_symbols[sname] = True
            if doc is None:
                doc = ""
            if len(doc) > 0:
                docstring_lookup[sname] = doc

        updated_tree = inspect_pyi(str(stub_fp), docstring_lookup)
        code = ast.unparse(updated_tree)
        with stub_fp.open("w") as f:
            f.write(code)

        keys_left, all_left = len(docstring_lookup.items()), len(all_symbols.items())
        if all_left > 0:
            msg = f"There are {all_left} symbols missing from the {str(stub_fp)}. Consider adding them:\n"
            for s in all_symbols.keys():
                msg += f"\t{s} {' -- has Rust docstring!' if docstring_lookup.get(s,None) is not None else ''}\n"
            logger.info(msg)
    logger.info("DONE :)")
