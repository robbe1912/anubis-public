#!/usr/bin/env python3
"""Fetch Python class methods for common packages and emit JSONL for symbol_bundle.

Source of truth: Python runtime `dir(module.Class)` — the same mechanism
the scanner uses at runtime via introspect_python_class, but pre-seeded
into the static bundle so the SQLite cache has comprehensive coverage
without requiring a subprocess on every scan.

Usage:
    python fetch_python_classes.py >> tests/fixtures/symbol_bundle.jsonl

Output: one JSON line per class method, matching the bundle schema:
    {"library":"pypi.pandas","version":"3.0.5","path":"DataFrame.agg",
     "name":"agg","kind":"Method",...}
"""
import json
import sys
import importlib

# Packages to fetch — keyed by library name (must match pypi.X convention).
# Each entry: package import name, list of class names to introspect.
PACKAGES = {
    "pandas": [
        "DataFrame", "Series", "Index", "RangeIndex", "MultiIndex",
        "DatetimeIndex", "TimedeltaIndex", "Categorical", "CategoricalIndex",
        "Period", "Timestamp", "Timedelta", "Interval",
        "ExcelFile", "ExcelWriter", "HDFStore", "StataReader",
        "read_csv", "read_json", "read_excel", "read_sql", "read_html",
        "read_parquet", "read_pickle", "read_hdf", "read_stata",
        "merge", "concat", "concat_objs", "pivot", "melt", "crosstab",
        "cut", "qcut", "date_range", "bdate_range", "period_range",
        "timedelta_range", "interval_range", "to_datetime", "to_numeric",
        "to_timedelta", "unique", "value_counts",
    ],
    "numpy": [
        "ndarray", "matrix", "chararray", "recarray", "memmap",
        "dtype", "number", "integer", "floating", "complex_",
        "bool_", "str_", "bytes_", "object_",
        "array", "asarray", "zeros", "ones", "empty", "full",
        "arange", "linspace", "logspace", "geomspace",
        "random", "fft", "linalg", "polynomial",
        "sin", "cos", "tan", "exp", "log", "sqrt", "abs", "sum",
        "mean", "std", "var", "min", "max", "argmin", "argmax",
        "dot", "cross", "inner", "outer", "matmul",
        "reshape", "flatten", "ravel", "transpose", "swapaxes",
    ],
    "sqlalchemy": [
        "Column", "Integer", "String", "Text", "Boolean", "DateTime",
        "Float", "Numeric", "LargeBinary", "PickleType", "Unicode",
        "UnicodeText", "Date", "Time", "Interval", "Enum", "JSON",
        "ForeignKey", "ForeignKeyConstraint", "UniqueConstraint",
        "PrimaryKeyConstraint", "CheckConstraint", "Index",
        "Table", "MetaData", "Sequence", "SchemaItem",
        "create_engine", "engine_from_config", "sessionmaker",
        "Session", "scoped_session", "orm",
        "select", "insert", "update", "delete", "func",
        "and_", "or_", "not_", "between", "case", "cast",
        "union", "union_all", "except_", "intersect",
        "exists", "literal", "text", "desc", "asc",
        "relationship", "backref", "joinedload", "subqueryload",
        "declarative_base", "composite",
    ],
    "sqlalchemy.orm": [
        "Session", "scoped_session", "sessionmaker", "mapper",
        "relationship", "column_property", "composite",
        "joinedload", "subqueryload", "selectinload", "lazyload",
        "contains_eager", "undefer", "undefer_group",
    ],
    "sqlalchemy.ext.asyncio": [
        "AsyncSession", "AsyncEngine", "AsyncConnection",
        "create_async_engine", "async_sessionmaker",
    ],
    "requests": [
        "Session", "Response", "Request", "PreparedRequest",
        "get", "post", "put", "patch", "delete", "head", "options",
        "request",
    ],
    "pydantic": [
        "BaseModel", "Field", "ConfigDict", "EmailStr", "SecretStr",
        "AnyUrl", "HttpUrl", "FileUrl", "model_validator",
        "field_validator", "field_serializer", "model_serializer",
        "computed_field", "model_dump", "model_dump_json",
        "model_validate", "model_validate_json", "model_json_schema",
        "model_rebuild", "model_copy", "model_fields",
        "model_construct", "model_post_init",
    ],
    "flask": [
        "Flask", "Blueprint", "request", "session", "g",
        "render_template", "redirect", "url_for", "abort",
        "flash", "jsonify", "make_response", "send_file",
        "send_from_directory", "Response",
        "current_app", "has_request_context", "has_app_context",
    ],
    "fastapi": [
        "FastAPI", "APIRouter", "Request", "Response",
        "HTTPException", "Depends", "Body", "Query", "Path",
        "Header", "Cookie", "Form", "File", "UploadFile",
        "BackgroundTasks", "WebSocket", "status",
    ],
    "click": [
        "Group", "Command", "Context", "Parameter", "Option",
        "Argument", "MultiCommand", "CommandCollection",
        "group", "command", "option", "argument", "pass_context",
        "pass_obj", "make_pass_decorator", "confirm", "prompt",
        "echo", "echo_via_pager", "edit", "launch", "get_text_stream",
        "CliRunner", "CliGroup", "Result",
    ],
    "matplotlib.pyplot": [
        "figure", "subplot", "subplots", "plot", "scatter", "bar",
        "barh", "hist", "pie", "boxplot", "violinplot",
        "imshow", "pcolormesh", "contour", "contourf",
        "xlabel", "ylabel", "title", "legend", "colorbar",
        "xlim", "ylim", "xticks", "yticks", "grid",
        "savefig", "show", "close", "clf", "cla",
        "twinx", "twiny", "suptitle", "figtext",
        "annotate", "text", "axhline", "axvline",
    ],
    "sklearn": [
        "fit", "predict", "transform", "fit_transform", "predict_proba",
        "score", "fit_predict", "fit_resample", "decision_function",
        "inverse_transform", "get_params", "set_params",
        "LogisticRegression", "RandomForestClassifier", "GradientBoostingClassifier",
        "SVC", "SVR", "LinearRegression", "Ridge", "Lasso",
        "KMeans", "DBSCAN", "PCA", "StandardScaler", "MinMaxScaler",
        "LabelEncoder", "OneHotEncoder", "OrdinalEncoder",
        "train_test_split", "cross_val_score", "GridSearchCV",
        "RandomizedSearchCV", "Pipeline", "ColumnTransformer",
        "SimpleImputer", "KNNImputer", "PolynomialFeatures",
    ],
    "django.http": [
        "HttpResponse", "JsonResponse", "HttpResponseRedirect",
        "HttpResponseBadRequest", "HttpResponseNotFound",
        "HttpResponseForbidden", "HttpResponseServerError",
        "HttpRequest", "QueryDict",
    ],
    "django.shortcuts": [
        "render", "redirect", "get_object_or_404", "get_list_or_404",
    ],
    "django.db.models": [
        "Model", "CharField", "IntegerField", "TextField",
        "BooleanField", "DateTimeField", "ForeignKey",
        "ManyToManyField", "OneToOneField", "EmailField",
        "URLField", "FloatField", "DecimalField",
        "AutoField", "BigAutoField", "UUIDField",
        "JSONField", "FileField", "ImageField",
        "Sum", "Count", "Avg", "Max", "Min",
        "Q", "F",
    ],
    "httpx": [
        "Client", "AsyncClient", "Response", "Request",
        "get", "post", "put", "patch", "delete", "head",
    ],
    "aiohttp": [
        "ClientSession", "ClientResponse", "ClientRequest",
        "web", "WSMsgType",
    ],
}

def emit_symbol(library, name, path, kind, params=None, return_type=None):
    """Emit one JSONL entry matching bundle schema."""
    entry = {
        "library": f"pypi.{library}",
        "version": "latest",
        "path": path,
        "name": name,
        "kind": kind,
        "signature": None,
        "params": params or [],
        "return_type": return_type,
        "doc_text": None,
        "source_file": None,
        "visibility": "Public",
        "is_deprecated": False,
        "deprecated_message": None,
        "extracted_at": 0,
    }
    print(json.dumps(entry))

def fetch_package(pkg_name, class_names):
    """Fetch methods for a package's classes via runtime introspection."""
    try:
        mod = importlib.import_module(pkg_name)
    except ImportError:
        print(f"# SKIP: {pkg_name} not installed", file=sys.stderr)
        return

    for cls_name in class_names:
        obj = getattr(mod, cls_name, None)
        if obj is None:
            # Might be a module-level function
            continue

        # If it's a class, emit its methods
        if isinstance(obj, type):
            emit_symbol(pkg_name, cls_name, cls_name, "Class")
            for method in sorted(dir(obj)):
                if method.startswith('_') and not method.startswith('__'):
                    continue  # Skip private (but keep dunder for __init__ etc.)
                if method.startswith('__') and method not in ('__init__', '__call__', '__str__', '__repr__'):
                    continue
                emit_symbol(pkg_name, method, f"{cls_name}.{method}", "Method")
        else:
            # Module-level function
            emit_symbol(pkg_name, cls_name, cls_name, "Function")

if __name__ == "__main__":
    for pkg, classes in PACKAGES.items():
        fetch_package(pkg, classes)
