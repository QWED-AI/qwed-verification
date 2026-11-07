"""
The modules and names Python code may use to be admitted (GHSA-9r7q).

CodeVerifier admits only code that is safe by shape. Lists of what is
dangerous (process execution, file and network access) cannot be complete:
io.FileIO, urllib3, pickle.Unpickler, multiprocessing and os.environ were
missing from them, and so were modules that other modules import under one of
their own names (random._os, typing.sys). So Python code is admitted only when
every module it imports is listed here and every name it uses from one is
listed for that module. Anything else is not admitted, third-party modules
included. The list holds standard-library modules that compute without
touching files, the network, processes, the environment or the import system,
and in each, the names that keep to that.

A module may be used only through its listed names. A module used as a value
(``m = json``, ``f(json)``) hands every attribute it has to code this check
does not follow, and so does one imported in a class body (``A.os``). A name
written into a module (``json.dumps = f``) changes what other code gets from
it. A frame or a traceback reaches the builtins and the caller's globals
(``g.gi_frame.f_builtins``), so those attributes are refused as well.

The builtins are listed the same way. Code may read only the builtins that
compute; ``open``, ``vars``, ``globals``, ``help``, ``license`` and the others
that reach files, code, modules or namespaces are refused, and so is any
builtin a later Python adds until it is listed.

So are special attributes (``__x__``): a function's globals or a bound
method's ``__reduce__`` (which returns the builtin getattr) leads from any
object to the builtins and every loaded module. And code may not read an
attribute by a name it makes at run time, through a format field, a class
pattern or a listed helper that reads attributes it is given by name.

A caller whose own runtime confines a module, such as the code-execution
sandbox and its import guard, can pass that module's name as trusted: it is
then not checked here. The other checks still apply.
"""

import ast
import builtins
import functools
import string
from typing import Any, Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple


def _names(text: str) -> FrozenSet[str]:
    """The space-separated names in ``text``."""
    return frozenset(text.split())


# Module -> the names code may use from it. A dotted key is a submodule; its
# parent is listed too. The names are each module's public API on Python 3.10
# to 3.15, less those that touch files, the network, processes or the
# environment, look an attribute up by a string, or are modules themselves.
ADMITTED_MODULES: Dict[str, FrozenSet[str]] = {
    "__future__": _names(
        "absolute_import all_feature_names annotations barry_as_FLUFL division generator_stop "
        "generators nested_scopes print_function unicode_literals with_statement"
    ),
    "abc": _names(
        "ABC ABCMeta abstractclassmethod abstractmethod abstractproperty abstractstaticmethod "
        "get_cache_token update_abstractmethods"
    ),
    "array": _names("ArrayType array typecodes"),
    # Not main, which reads a file named on the command line, or iter_fields,
    # which reads the attributes an object's _fields names.
    "ast": _names(
        "AST Add And AnnAssign Assert Assign AsyncFor AsyncFunctionDef AsyncWith Attribute "
        "AugAssign AugLoad AugStore Await BinOp BitAnd BitOr BitXor BoolOp Break Bytes Call "
        "ClassDef Compare Constant Continue Del Delete Dict DictComp Div Ellipsis Eq "
        "ExceptHandler Expr Expression ExtSlice FloorDiv For FormattedValue FunctionDef "
        "FunctionType GeneratorExp Global Gt GtE If IfExp Import ImportFrom In Index Interactive "
        "Interpolation Invert Is IsNot JoinedStr LShift Lambda List ListComp Load Lt LtE MatMult "
        "Match MatchAs MatchClass MatchMapping MatchOr MatchSequence MatchSingleton MatchStar "
        "MatchValue Mod Module Mult Name NameConstant NamedExpr NodeTransformer NodeVisitor "
        "Nonlocal Not NotEq NotIn Num Or Param ParamSpec Pass Pow PyCF_ALLOW_TOP_LEVEL_AWAIT "
        "PyCF_ONLY_AST PyCF_OPTIMIZED_AST PyCF_TYPE_COMMENTS RShift Raise Return Set SetComp "
        "Slice Starred Store Str Sub Subscript Suite TemplateStr Try TryStar Tuple TypeAlias "
        "TypeIgnore TypeVar TypeVarTuple UAdd USub UnaryOp While With Yield YieldFrom alias arg "
        "arguments boolop cmpop compare comprehension copy_location dump excepthandler expr "
        "expr_context fix_missing_locations get_docstring get_source_segment increment_lineno "
        "iter_child_nodes keyword literal_eval match_case mod operator parse pattern "
        "slice stmt type_ignore type_param unaryop unparse walk withitem"
    ),
    "base64": _names(
        "a85decode a85encode b16decode b16encode b32decode b32encode b32hexdecode b32hexencode "
        "b64decode b64encode b85decode b85encode decode decodebytes encode encodebytes "
        "standard_b64decode standard_b64encode urlsafe_b64decode urlsafe_b64encode z85decode z85encode"
    ),
    "binascii": _names(
        "ASCII85_ALPHABET BASE32HEX_ALPHABET BASE32_ALPHABET BASE64_ALPHABET BASE85_ALPHABET "
        "BINHEX_ALPHABET CRYPT_ALPHABET Error Incomplete URLSAFE_BASE64_ALPHABET UU_ALPHABET "
        "Z85_ALPHABET a2b_ascii85 a2b_base32 a2b_base64 a2b_base85 a2b_hex a2b_hqx a2b_qp a2b_uu "
        "b2a_ascii85 b2a_base32 b2a_base64 b2a_base85 b2a_hex b2a_hqx b2a_qp b2a_uu crc32 crc_hqx "
        "hexlify rlecode_hqx rledecode_hqx unhexlify"
    ),
    "bisect": _names("bisect bisect_left bisect_right insort insort_left insort_right"),
    # Compression in memory; not open or the file classes.
    "bz2": _names("BZ2Compressor BZ2Decompressor compress decompress"),
    "calendar": _names(
        "APRIL AUGUST Calendar DECEMBER Day FEBRUARY FRIDAY HTMLCalendar IllegalMonthError "
        "IllegalWeekdayError JANUARY JULY JUNE LocaleHTMLCalendar LocaleTextCalendar MARCH MAY "
        "MONDAY Month NOVEMBER OCTOBER SATURDAY SEPTEMBER SUNDAY THURSDAY TUESDAY TextCalendar "
        "WEDNESDAY calendar day_abbr day_name firstweekday isleap leapdays month month_abbr "
        "month_name monthcalendar monthrange prcal prmonth setfirstweekday standalone_month_abbr "
        "standalone_month_name timegm weekday weekheader"
    ),
    "cmath": _names(
        "acos acosh asin asinh atan atanh cos cosh e exp inf infj isclose isfinite isinf isnan "
        "log log10 nan nanj phase pi polar rect sin sinh sqrt tan tanh tau"
    ),
    "collections": _names(
        "ChainMap Counter OrderedDict UserDict UserList UserString defaultdict deque namedtuple"
    ),
    "collections.abc": _names(
        "AsyncGenerator AsyncIterable AsyncIterator Awaitable Buffer ByteString Callable "
        "Collection Container Coroutine Generator Hashable ItemsView Iterable Iterator KeysView "
        "Mapping MappingView MutableMapping MutableSequence MutableSet Reversible Sequence Set "
        "Sized ValuesView"
    ),
    # Not chdir, which changes the process's working directory, or
    # redirect_stdout and redirect_stderr, which keep the stream they replace.
    "contextlib": _names(
        "AbstractAsyncContextManager AbstractContextManager AsyncExitStack ContextDecorator "
        "ExitStack aclosing asynccontextmanager closing contextmanager nullcontext suppress"
    ),
    # Not copy, which rebuilds a bound method by getattr(self, its function's
    # __name__), a name code can set.
    "copy": _names("Error deepcopy replace"),
    "csv": _names(
        "Dialect DictReader DictWriter Error QUOTE_ALL QUOTE_MINIMAL QUOTE_NONE QUOTE_NONNUMERIC "
        "QUOTE_NOTNULL QUOTE_STRINGS Sniffer excel excel_tab field_size_limit get_dialect "
        "list_dialects reader register_dialect unix_dialect unregister_dialect writer"
    ),
    # Not make_dataclass, whose field names are made at run time; asdict,
    # astuple and replace read the fields by name. dataclass itself is
    # admitted as a class decorator only (DECORATOR_ONLY).
    "dataclasses": _names(
        "Field FrozenInstanceError InitVar KW_ONLY MISSING asdict astuple dataclass field fields "
        "is_dataclass replace"
    ),
    "datetime": _names("MAXYEAR MINYEAR UTC date datetime time timedelta timezone tzinfo"),
    "decimal": _names(
        "BasicContext Clamped Context ConversionSyntax Decimal DecimalException DecimalTuple "
        "DefaultContext DivisionByZero DivisionImpossible DivisionUndefined ExtendedContext "
        "FloatOperation HAVE_CONTEXTVAR HAVE_THREADS IEEEContext IEEE_CONTEXT_MAX_BITS Inexact "
        "InvalidContext InvalidOperation MAX_EMAX MAX_PREC MIN_EMIN MIN_ETINY Overflow ROUND_05UP "
        "ROUND_CEILING ROUND_DOWN ROUND_FLOOR ROUND_HALF_DOWN ROUND_HALF_EVEN ROUND_HALF_UP "
        "ROUND_UP Rounded SPEC_VERSION Subnormal Underflow getcontext localcontext setcontext"
    ),
    "difflib": _names(
        "Differ HtmlDiff IS_CHARACTER_JUNK IS_LINE_JUNK Match SequenceMatcher context_diff "
        "diff_bytes get_close_matches ndiff restore unified_diff"
    ),
    # Not global_enum, which writes members into the module a class names, or
    # pickle_by_enum_name, which returns the builtin getattr.
    "enum": _names(
        "CONFORM CONTINUOUS EJECT Enum EnumCheck EnumDict EnumMeta EnumType Flag FlagBoundary "
        "IntEnum IntFlag KEEP NAMED_FLAGS ReprEnum STRICT StrEnum UNIQUE auto bin "
        "global_enum_repr global_flag_repr global_str member nonmember pickle_by_global_name "
        "property show_flag_values unique verify"
    ),
    "fractions": _names("Fraction"),
    # singledispatch is admitted here; the strings typing evaluates are checked
    # on their own (GHSA-p75q). Not update_wrapper, which reads and copies the
    # attributes it is given by name; wraps is admitted as a function
    # decorator only (DECORATOR_ONLY).
    "functools": _names(
        "Placeholder WRAPPER_ASSIGNMENTS WRAPPER_UPDATES cache cached_property cmp_to_key "
        "lru_cache partial partialmethod reduce singledispatch singledispatchmethod "
        "total_ordering wraps"
    ),
    "graphlib": _names("CycleError TopologicalSorter"),
    "gzip": _names("BadGzipFile compress decompress"),
    "hashlib": _names(
        "algorithms_available algorithms_guaranteed blake2b blake2s file_digest md5 new "
        "pbkdf2_hmac scrypt sha1 sha224 sha256 sha384 sha3_224 sha3_256 sha3_384 sha3_512 sha512 "
        "shake_128 shake_256"
    ),
    "heapq": _names(
        "heapify heapify_max heappop heappop_max heappush heappush_max heappushpop "
        "heappushpop_max heapreplace heapreplace_max merge nlargest nsmallest"
    ),
    "hmac": _names("HMAC compare_digest digest digest_size new trans_36 trans_5C"),
    "html": _names("escape unescape"),
    # In-memory streams only: FileIO and open reach files, and the buffered and
    # text wrappers wrap a stream code could not otherwise use.
    "io": _names("BytesIO DEFAULT_BUFFER_SIZE SEEK_CUR SEEK_END SEEK_SET StringIO UnsupportedOperation"),
    "ipaddress": _names(
        "AddressValueError IPV4LENGTH IPV6LENGTH IPv4Address IPv4Interface IPv4Network "
        "IPv6Address IPv6Interface IPv6Network NetmaskValueError collapse_addresses "
        "get_mixed_type_key ip_address ip_interface ip_network summarize_address_range "
        "v4_int_to_packed v6_int_to_packed"
    ),
    "itertools": _names(
        "accumulate batched chain combinations combinations_with_replacement compress count "
        "cycle dropwhile filterfalse groupby islice pairwise permutations product repeat starmap "
        "takewhile tee zip_longest"
    ),
    "json": _names("JSONDecodeError JSONDecoder JSONEncoder dump dumps load loads"),
    "keyword": _names("iskeyword issoftkeyword kwlist softkwlist"),
    "lzma": _names(
        "CHECK_CRC32 CHECK_CRC64 CHECK_ID_MAX CHECK_NONE CHECK_SHA256 CHECK_UNKNOWN FILTER_ARM "
        "FILTER_ARMTHUMB FILTER_DELTA FILTER_IA64 FILTER_LZMA1 FILTER_LZMA2 FILTER_POWERPC "
        "FILTER_SPARC FILTER_X86 FORMAT_ALONE FORMAT_AUTO FORMAT_RAW FORMAT_XZ LZMACompressor "
        "LZMADecompressor LZMAError MF_BT2 MF_BT3 MF_BT4 MF_HC3 MF_HC4 MODE_FAST MODE_NORMAL "
        "PRESET_DEFAULT PRESET_EXTREME compress decompress is_check_supported"
    ),
    # integer is Python 3.15's submodule of integer functions.
    "math": _names(
        "acos acosh asin asinh atan atan2 atanh cbrt ceil comb copysign cos cosh degrees dist e "
        "erf erfc exp exp2 expm1 fabs factorial floor fma fmax fmin fmod frexp fsum gamma gcd "
        "hypot inf integer isclose isfinite isinf isnan isnormal isqrt issubnormal lcm ldexp lgamma log "
        "log10 log1p log2 modf nan nextafter perm pi pow prod radians remainder signbit sin sinh "
        "sqrt sumprod tan tanh tau trunc ulp"
    ),
    "numbers": _names("Complex Integral Number Rational Real"),
    # Not attrgetter or methodcaller, which look an attribute up by a string.
    "operator": _names(
        "abs add and_ call concat contains countOf delitem eq floordiv ge getitem gt iadd iand "
        "iconcat ifloordiv ilshift imatmul imod imul index indexOf inv invert ior ipow irshift "
        "is_ is_none is_not is_not_none isub itemgetter itruediv ixor le length_hint lshift lt "
        "matmul mod mul ne neg not_ or_ pos pow rshift setitem sub truediv truth xor"
    ),
    # Path strings only: nothing that reads the file system, the working
    # directory or the environment.
    "os": _names("altsep curdir devnull extsep fspath linesep name pardir pathsep sep"),
    "os.path": _names(
        "altsep basename commonpath commonprefix curdir devnull dirname extsep isabs join "
        "normcase normpath pardir pathsep sep split splitdrive splitext splitroot "
        "supports_unicode_filenames"
    ),
    # Not PrettyPrinter, which keeps the stream it writes to.
    "pprint": _names("isreadable isrecursive pformat pp pprint saferepr"),
    "random": _names(
        "Random SystemRandom betavariate binomialvariate choice choices expovariate gammavariate "
        "gauss getrandbits getstate lognormvariate normalvariate paretovariate randbytes randint "
        "random randrange sample seed setstate shuffle triangular uniform vonmisesvariate "
        "weibullvariate"
    ),
    # re.compile is admitted here; CodeVerifier still checks its call shape.
    "re": _names(
        "A ASCII DOTALL I IGNORECASE L LOCALE M MULTILINE Match NOFLAG Pattern PatternError "
        "RegexFlag S U UNICODE VERBOSE X compile error escape findall finditer fullmatch match "
        "prefixmatch purge search split sub subn template"
    ),
    "reprlib": _names("Repr recursive_repr repr"),
    "secrets": _names(
        "SystemRandom choice compare_digest randbelow randbits token_bytes token_hex token_urlsafe"
    ),
    "statistics": _names(
        "NormalDist StatisticsError correlation covariance fmean geometric_mean harmonic_mean kde "
        "kde_random linear_regression mean median median_grouped median_high median_low mode "
        "multimode pstdev pvariance quantiles stdev variance"
    ),
    # Not Formatter, whose get_field looks attributes up by a string.
    "string": _names(
        "Template ascii_letters ascii_lowercase ascii_uppercase capwords digits hexdigits "
        "octdigits printable punctuation whitespace"
    ),
    "struct": _names("Struct calcsize error iter_unpack pack pack_into unpack unpack_from"),
    # Not stdin, stdout or stderr: their buffers hold the file object, and its
    # type opens any path.
    "sys": _names(
        "argv byteorder exc_info exception exit float_info float_repr_style getdefaultencoding "
        "getrecursionlimit getsizeof hash_info hexversion implementation int_info maxsize "
        "maxunicode platform version version_info"
    ),
    "textwrap": _names("TextWrapper dedent fill indent shorten wrap"),
    "time": _names(
        "altzone asctime ctime daylight get_clock_info gmtime localtime mktime monotonic "
        "monotonic_ns perf_counter perf_counter_ns process_time process_time_ns sleep strftime "
        "strptime struct_time thread_time thread_time_ns time time_ns timezone tzname"
    ),
    # Types to compare with; not those that build code, functions or modules,
    # or MethodType, which binds a function to any object.
    "types": _names(
        "AsyncGeneratorType BuiltinFunctionType BuiltinMethodType CoroutineType "
        "DynamicClassAttribute EllipsisType GeneratorType GenericAlias MappingProxyType "
        "NoneType NotImplementedType SimpleNamespace UnionType coroutine"
    ),
    # Not get_type_hints or evaluate_forward_ref, which evaluate strings.
    # ForwardRef, TypeVar and the others that take a string are checked on
    # their own (GHSA-p75q).
    "typing": _names(
        "AbstractSet Annotated Any AnyStr AsyncContextManager AsyncGenerator AsyncIterable "
        "AsyncIterator Awaitable BinaryIO ByteString Callable ChainMap ClassVar Collection "
        "Concatenate Container ContextManager Coroutine Counter DefaultDict Deque Dict Final "
        "ForwardRef FrozenSet Generator Generic Hashable IO ItemsView Iterable Iterator KeysView "
        "List Literal LiteralString Mapping MappingView Match MutableMapping MutableSequence "
        "MutableSet NamedTuple Never NewType NoDefault NoExtraItems NoReturn NotRequired Optional "
        "OrderedDict ParamSpec ParamSpecArgs ParamSpecKwargs Pattern Protocol ReadOnly Required "
        "Reversible Self Sequence Set Sized SupportsAbs SupportsBytes SupportsComplex "
        "SupportsFloat SupportsIndex SupportsInt SupportsRound TYPE_CHECKING Text TextIO Tuple "
        "Type TypeAlias TypeAliasType TypeForm TypeGuard TypeIs TypeVar TypeVarTuple TypedDict "
        "Union Unpack ValuesView assert_never assert_type cast clear_overloads dataclass_transform "
        "disjoint_base final get_args get_origin get_overloads get_protocol_members is_protocol "
        "is_typeddict no_type_check no_type_check_decorator overload override reveal_type "
        "runtime_checkable"
    ),
    "unicodedata": _names(
        "UCD bidirectional block category combining decimal decomposition digit east_asian_width "
        "extended_pictographic grapheme_cluster_break indic_conjunct_break is_normalized "
        "isxidcontinue isxidstart iter_graphemes lookup mirrored name normalize numeric ucd_3_2_0 "
        "unidata_version"
    ),
    "urllib": frozenset(),
    "urllib.parse": _names(
        "DefragResult DefragResultBytes ParseResult ParseResultBytes SplitResult "
        "SplitResultBytes parse_qs parse_qsl quote quote_from_bytes quote_plus unquote "
        "unquote_plus unquote_to_bytes urldefrag urlencode urljoin urlparse urlsplit urlunparse "
        "urlunsplit"
    ),
    # Not uuid1, uuid6 or getnode, which can run a program to read the MAC
    # address.
    "uuid": _names(
        "MAX NAMESPACE_DNS NAMESPACE_OID NAMESPACE_URL NAMESPACE_X500 NIL RESERVED_FUTURE "
        "RESERVED_MICROSOFT RESERVED_NCS RFC_4122 SafeUUID UUID uuid3 uuid4 uuid5 uuid7 uuid8"
    ),
    "zlib": _names(
        "DEFLATED DEF_BUF_SIZE DEF_MEM_LEVEL MAX_WBITS ZLIBNG_VERSION ZLIB_RUNTIME_VERSION "
        "ZLIB_VERSION Z_BEST_COMPRESSION Z_BEST_SPEED Z_BLOCK Z_DEFAULT_COMPRESSION "
        "Z_DEFAULT_STRATEGY Z_FILTERED Z_FINISH Z_FIXED Z_FULL_FLUSH Z_HUFFMAN_ONLY "
        "Z_NO_COMPRESSION Z_NO_FLUSH Z_PARTIAL_FLUSH Z_RLE Z_SYNC_FLUSH Z_TREES adler32 "
        "adler32_combine compress compressobj crc32 crc32_combine decompress decompressobj error"
    ),
}

# Modules a star import may name: every name it binds from them (their
# __all__, or every public name where there is none) is listed above, on
# Python 3.10 to 3.15. From any other module it would bind names this check
# does not see. Not time: on Linux it also binds clock_settime and tzset.
STAR_IMPORT_MODULES: FrozenSet[str] = _names(
    "abc array base64 binascii bisect calendar cmath collections collections.abc csv "
    "datetime decimal difflib fractions graphlib hashlib heapq hmac "
    "html itertools json keyword math numbers random re reprlib secrets statistics struct "
    "textwrap unicodedata urllib.parse zlib"
)

# A frame reaches the builtins, its globals and its caller's frame; a
# generator, coroutine or traceback reaches a frame.
FRAME_ATTRIBUTES: FrozenSet[str] = _names(
    "__traceback__ ag_code ag_frame cr_code cr_frame f_back f_builtins f_code f_globals "
    "f_locals f_trace gi_code gi_frame tb_frame tb_next"
)

# The builtins code may read: the public exceptions, and the builtins that
# compute.
ADMITTED_BUILTINS: FrozenSet[str] = _names(
    "ArithmeticError AssertionError AttributeError BaseException BaseExceptionGroup "
    "BlockingIOError BrokenPipeError BufferError BytesWarning ChildProcessError "
    "ConnectionAbortedError ConnectionError ConnectionRefusedError ConnectionResetError "
    "DeprecationWarning EOFError EncodingWarning EnvironmentError Exception ExceptionGroup "
    "FileExistsError FileNotFoundError FloatingPointError FutureWarning GeneratorExit IOError "
    "ImportCycleError ImportError ImportWarning IndentationError IndexError InterruptedError "
    "IsADirectoryError KeyError KeyboardInterrupt LookupError MemoryError ModuleNotFoundError "
    "NameError NotADirectoryError NotImplementedError OSError OverflowError "
    "PendingDeprecationWarning PermissionError ProcessLookupError PythonFinalizationError "
    "RecursionError ReferenceError ResourceWarning RuntimeError RuntimeWarning "
    "StopAsyncIteration StopIteration SyntaxError SyntaxWarning SystemError SystemExit "
    "TabError TimeoutError TypeError UnboundLocalError UnicodeDecodeError UnicodeEncodeError "
    "UnicodeError UnicodeTranslateError UnicodeWarning UserWarning ValueError Warning "
    "WindowsError ZeroDivisionError "
    "Ellipsis False None NotImplemented True __debug__ __doc__ __name__ __package__ abs aiter "
    "all anext any ascii bin bool bytearray bytes callable chr classmethod complex dict dir "
    "divmod enumerate exit filter float format frozendict frozenset hasattr hash hex id input "
    "int isinstance issubclass iter len list map max min next object oct ord pow print "
    "property quit range repr reversed round sentinel set slice sorted staticmethod str sum "
    "super tuple type zip"
)

# The other builtins on Python 3.10 to 3.15. open opens files; eval, exec,
# compile, __import__, __lazy_import__ and __build_class__ run code or import
# it, and __loader__ and __spec__ import it; getattr, setattr and delattr take
# an attribute's name as a string; globals, locals and vars hand out a
# namespace dict and every object in it, modules and the builtins included;
# memoryview reaches raw memory. Of the interactive prompt's helpers, license,
# credits and copyright read the files listed on them, help imports a module
# named by a string, and breakpoint starts the debugger (exit and quit only
# raise SystemExit). IPython puts get_ipython in the builtins, which returns
# its shell.
REFUSED_BUILTINS: FrozenSet[str] = _names(
    "_IncompleteInputError __build_class__ __import__ __lazy_import__ __loader__ __spec__ "
    "breakpoint compile copyright credits delattr eval exec get_ipython getattr globals help "
    "license locals memoryview open setattr vars"
)

# Every builtin name, so that code checked on one Python is checked for the
# builtins of another.
BUILTIN_NAMES: FrozenSet[str] = ADMITTED_BUILTINS | REFUSED_BUILTINS

# A builtin's name is refused wherever it is read, bound in the code or not:
# at module or class level a name falls back to the builtin while the code
# has not bound it, and this check does not follow which binding runs first.
# A builtin a later Python adds is refused until it is listed. (_ is left
# out: an interactive session keeps its last result there.)
_ALL_BUILTIN_NAMES: FrozenSet[str] = BUILTIN_NAMES | (frozenset(dir(builtins)) - {"_"})
_REFUSED_BUILTINS: FrozenSet[str] = _ALL_BUILTIN_NAMES - ADMITTED_BUILTINS

# Special attributes (__name__) code may read. One not listed reaches what
# the code does not name: a function's globals, closure or defaults, the
# builtin getattr (a bound method's __reduce__ returns it), a function bound
# to any object (__get__), or a class's namespace and subclasses. The
# protocol methods and plain data are listed; a special attribute a later
# Python adds is refused until it is listed.
_PROTOCOL_DUNDERS: FrozenSet[str] = _names(
    "__abs__ __add__ __aenter__ __aexit__ __aiter__ __and__ __anext__ __await__ __bool__ "
    "__bytes__ __call__ __ceil__ __complex__ __contains__ __copy__ __deepcopy__ __delitem__ "
    "__dir__ __divmod__ __enter__ __eq__ __exit__ __float__ __floor__ __floordiv__ __format__ "
    "__fspath__ __ge__ __getitem__ __gt__ __hash__ __iadd__ __iand__ __ifloordiv__ __ilshift__ "
    "__imatmul__ __imod__ __imul__ __index__ __init__ __init_subclass__ __int__ __invert__ "
    "__ior__ __ipow__ __irshift__ __isub__ __iter__ __itruediv__ __ixor__ __le__ __len__ "
    "__length_hint__ __lshift__ __lt__ __matmul__ __missing__ __mod__ __mul__ __ne__ __neg__ "
    "__new__ __next__ __or__ __pos__ __post_init__ __pow__ __radd__ __rand__ __rdivmod__ "
    "__repr__ __reversed__ __rfloordiv__ __rlshift__ __rmatmul__ __rmod__ __rmul__ __ror__ "
    "__round__ __rpow__ __rrshift__ __rshift__ __rsub__ __rtruediv__ __rxor__ __setitem__ "
    "__sizeof__ __str__ __sub__ __truediv__ __trunc__ __xor__"
)
ADMITTED_DUNDERS: FrozenSet[str] = _PROTOCOL_DUNDERS | _names(
    "__all__ __args__ __cause__ __context__ __doc__ __match_args__ __members__ __module__ "
    "__mro__ __name__ __notes__ __origin__ __parameters__ __qualname__ __slots__ "
    "__suppress_context__ __version__"
)
# Special attributes code may assign or delete: the protocol methods and the
# names a decorator copies onto its wrapper. Not data that stdlib code reads
# attribute names from, such as __match_args__ for a class pattern.
WRITABLE_DUNDERS: FrozenSet[str] = _PROTOCOL_DUNDERS | _names("__doc__ __module__ __name__ __qualname__")

# Private methods of listed classes and their metaclasses that read the
# module table or a frame, write to a standard stream, or evaluate, compile
# or look attributes up by a name they are given (enum.Enum._convert_ reads
# any loaded module's namespace). Found by scanning their code on Python
# 3.10 to 3.15; refused by name, on any object.
REFLECTIVE_PRIVATES: FrozenSet[str] = _names(
    "_add_member_ _compile_pattern _convert_ _create_ _determine_new_args _evaluate _find_new_ "
    "_fix_up_module _fstring_FormattedValue _fstring_JoinedStr _get_theme "
    "_guess_quote_and_delimiter _make_substitution _new_member_ _pprint_dataclass "
    "_resolve_filename _safe_repr"
)
# Under IPython and Jupyter, exit and quit hold the shell, which runs
# commands, in _ip; refused by name, on any object.
_RUNNER_PRIVATES: FrozenSet[str] = _names("_ip")

# The listed classes that define one of REFLECTIVE_PRIVATES, or whose
# metaclass does (Enum's metaclass defines _convert_). Found by scanning the
# listed modules on Python 3.10 to 3.15; a test rescans the running Python.
CLASSES_WITH_REFLECTIVE_PRIVATES: FrozenSet[str] = _names(
    "calendar.Day calendar.Month csv.Sniffer enum.Enum enum.EnumCheck enum.EnumMeta enum.EnumType "
    "enum.Flag enum.FlagBoundary enum.IntEnum enum.IntFlag enum.ReprEnum enum.StrEnum "
    "re.RegexFlag string.Template typing.ForwardRef uuid.SafeUUID"
)

# str.format and format_map read the attribute a field names
# ("{0.__globals__}"), so their template must be a string written in the
# code, or a name bound only to such strings, with no attribute in a field.
_FORMAT_METHODS: FrozenSet[str] = frozenset({"format", "format_map"})
_FORMATTER = string.Formatter()
# Python itself refuses a field nested deeper than this in a format spec.
_MAX_FORMAT_NESTING = 2

# Listed names that read or copy attributes by a name they are given unless
# they decorate a statement: dataclass on a class reads only the fields
# written there, and wraps, given one function, copies fixed names. A
# dataclass's bases must be classes that hold none of the privates above
# (asdict reads a field by the name its Field holds, which code can change).
DECORATOR_ONLY: Dict[str, Tuple[type, ...]] = {
    "dataclasses.dataclass": (ast.ClassDef,),
    "functools.wraps": (ast.FunctionDef, ast.AsyncFunctionDef),
}

_DESCRIPTIONS = {
    "module_not_admitted": "Import of a module that admitted code may not use",
    "attribute_not_admitted": "Use of a module name that admitted code may not use",
    "module_reference": "A module used as a value; admitted code may use only its listed names",
    "module_write": "Assignment to or deletion of a module's name",
    "builtin_not_admitted": "Use of a builtin that admitted code may not use",
    "frame_introspection": "Frame or traceback introspection, which reaches the builtins and the caller's globals",
    "special_attribute": "Use of a special or private attribute that admitted code may not use",
    "dynamic_lookup": (
        "An attribute read by a name the code makes at run time (format fields, class patterns, "
        "decorator helpers)"
    ),
}
_RECOMMENDATION = (
    "Use only the standard-library modules and names QWED admits; route anything else "
    "through a reviewed, sandboxed tool."
)

_Finding = Tuple[str, str]


def findings(nodes: Iterable[ast.AST], trusted: FrozenSet[str] = frozenset()) -> List[Dict[str, Any]]:
    """CodeVerifier findings for what in ``nodes`` (every node of the
    module's AST) the lists do not admit: imports, module names and values,
    builtins, special and private attributes, frame reads, and attributes
    read by a name made at run time. Modules whose top-level name is in
    ``trusted`` are not checked; the other checks still apply to them."""
    nodes = list(nodes)
    found: Dict[Tuple[str, str, Optional[int]], Dict[str, Any]] = {}
    bindings = _import_bindings(nodes, trusted, found)
    scope = _Scope(nodes, bindings)
    # Attribute chains are checked whole, from their outermost node.
    inner = {id(node.value) for node in nodes if isinstance(node, ast.Attribute)}
    for node in nodes:
        for finding, line in _node_findings(node, trusted) + _reflection_findings(node, scope):
            _add(found, finding, line)
        if isinstance(node, (ast.Name, ast.Attribute)) and id(node) not in inner:
            targets = _chain_targets(node, bindings)
            finding = _chain_finding(node, targets, trusted) or _decorator_only_finding(node, targets, scope)
            if finding:
                _add(found, finding, node.lineno)
    return list(found.values())


def _node_findings(node: ast.AST, trusted: FrozenSet[str]) -> List[Tuple[_Finding, int]]:
    """A builtin read that is not admitted; a frame or traceback attribute
    read, by name or in a class pattern; and a module imported in a class
    body, which is the class's attribute (A.os) and so reached without its
    import name."""
    builtin = _builtin_read(node)
    if builtin:
        return [(("builtin_not_admitted", builtin), node.lineno)]
    if isinstance(node, ast.Attribute) and node.attr in FRAME_ATTRIBUTES:
        return [(("frame_introspection", node.attr), node.lineno)]
    if isinstance(node, ast.MatchClass):
        return [(("frame_introspection", attr), node.lineno) for attr in node.kwd_attrs if attr in FRAME_ATTRIBUTES]
    if isinstance(node, ast.ClassDef):
        return [(("module_reference", module), line) for module, line in _modules_bound_in_class_body(node, trusted)]
    return []


def _builtin_read(node: ast.AST) -> Optional[str]:
    """The builtin not admitted that ``node`` reads, if any. An augmented
    assignment reads its target first (help += x hands help to x.__radd__)."""
    if isinstance(node, ast.AugAssign):
        node = node.target
    elif not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
        return None
    if isinstance(node, ast.Name) and node.id in _REFUSED_BUILTINS:
        return node.id
    return None


def _modules_bound_in_class_body(cls: ast.ClassDef, trusted: FrozenSet[str]) -> List[Tuple[str, int]]:
    """The listed modules an import in ``cls``'s own body binds, with their
    lines."""
    bound: List[Tuple[str, int]] = []
    for node in _class_scope(cls):
        if isinstance(node, ast.Import):
            bound.extend((alias.name, node.lineno) for alias in node.names if alias.name in ADMITTED_MODULES)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            bound.extend(
                (f"{node.module}.{alias.name}", node.lineno) for alias in node.names
                if f"{node.module}.{alias.name}" in ADMITTED_MODULES
            )
    return [(module, line) for module, line in bound if module.split(".")[0] not in trusted]


def _class_scope(cls: ast.ClassDef) -> Iterator[ast.AST]:
    """The nodes in ``cls``'s own scope; functions, classes and lambdas
    defined in it have their own."""
    pending: List[ast.AST] = list(cls.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


# --- attributes read by a name: special and private names, format fields,
# class patterns and decorator helpers ---------------------------------------

# Statements that bind their own name (def, class, except ... as, case
# captures). Not a Python 3.12 type parameter (def f[T]): it binds T only
# inside the definition it parameterises, as a TypeVar, which is no class,
# string or module there, so it does not count as a binding of T elsewhere.
_NAMED_BINDINGS: Tuple[type, ...] = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler, ast.MatchAs, ast.MatchStar,
)


class _Scope:
    """What the reflection checks need to know about the whole code: where
    each name is bound, which statements decorate what, and which classes
    have a fixed __match_args__ (static) or may be a dataclass's base (safe).
    Each index is built the first time a check needs it; most code needs
    none of them."""

    def __init__(self, nodes: List[ast.AST], bindings: Dict[str, Set[str]]):
        """Keep ``nodes`` and the admitted import ``bindings``."""
        self.nodes = nodes
        self.bindings = bindings
        self.templates: Dict[str, bool] = {}  # name -> bound only to fixed templates

    @functools.cached_property
    def parents(self) -> Dict[int, ast.AST]:
        """Each node's parent, by the child's id."""
        return {id(child): parent for parent in self.nodes for child in ast.iter_child_nodes(parent)}

    @functools.cached_property
    def sites(self) -> Dict[str, List[ast.AST]]:
        """The nodes that bind each name."""
        sites: Dict[str, List[ast.AST]] = {}
        for node in self.nodes:
            for name in _bound_names(node):
                sites.setdefault(name, []).append(node)
        return sites

    @functools.cached_property
    def star(self) -> bool:
        """Whether a star import binds names this check does not see."""
        return "*" in self.sites

    @functools.cached_property
    def decorations(self) -> Dict[int, Tuple[ast.AST, Optional[ast.Call]]]:
        """For each decorator's name node, the statement it decorates and the
        call it is the function of, if any."""
        found: Dict[int, Tuple[ast.AST, Optional[ast.Call]]] = {}
        for node in self.nodes:
            for decorator in getattr(node, "decorator_list", ()):
                call = decorator if isinstance(decorator, ast.Call) else None
                found[id(call.func if call else decorator)] = (node, call)
        return found

    @functools.cached_property
    def classes(self) -> Tuple[Set[str], Set[str]]:
        """The static and the safe class statements' names."""
        return _settle_classes(self)

    @property
    def static(self) -> Set[str]:
        """Classes whose __match_args__ code cannot set at run time."""
        return self.classes[0]

    @property
    def safe(self) -> Set[str]:
        """Static classes that may be a dataclass's base."""
        return self.classes[1]

    def bound_only_by(self, name: str, node: ast.AST) -> bool:
        """Whether ``node`` is the only statement that binds ``name``."""
        return not self.star and self.sites.get(name) == [node]

    def import_bound(self, name: str) -> bool:
        """Whether ``name`` is bound by admitted imports and nothing else."""
        return (
            not self.star and name in self.bindings
            and all(isinstance(site, (ast.Import, ast.ImportFrom)) for site in self.sites.get(name, ()))
        )


def _bound_names(node: ast.AST) -> List[str]:
    """The names ``node`` binds ("*" for a star import)."""
    if isinstance(node, ast.Name):
        return [] if isinstance(node.ctx, ast.Load) else [node.id]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [alias.asname or alias.name.split(".")[0] for alias in node.names]
    if isinstance(node, ast.arg):
        return [node.arg]
    name = node.rest if isinstance(node, ast.MatchMapping) else getattr(node, "name", None)
    return [name] if isinstance(node, (ast.MatchMapping, *_NAMED_BINDINGS)) and name else []


def _reflection_findings(node: ast.AST, scope: _Scope) -> List[Tuple[_Finding, int]]:
    """A special or private attribute not admitted, read or written, by name
    or in a class pattern; a format template that is not a fixed string or
    reads an attribute; a class pattern with positional parts on a class
    whose __match_args__ is not fixed; and a dataclass field with such a name."""
    if isinstance(node, ast.Attribute):
        found = [_special_name_finding(node.attr, not isinstance(node.ctx, ast.Load)), _format_finding(node, scope)]
    elif isinstance(node, ast.MatchClass):
        found = [_special_name_finding(attr, False) for attr in node.kwd_attrs]
        found.append(_class_pattern_finding(node, scope))
    elif isinstance(node, ast.ClassDef) and _is_dataclass(node, scope):
        found = [
            _special_name_finding(field.target.id, False) for field in _class_scope(node)
            if isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name)
        ]
    else:
        return []
    return [(finding, node.lineno) for finding in found if finding]


def _special_name_finding(name: str, write: bool) -> Optional[_Finding]:
    """The finding for an attribute named ``name``, read or written."""
    if len(name) > 4 and name.startswith("__") and name.endswith("__"):
        listed = WRITABLE_DUNDERS if write else ADMITTED_DUNDERS
        return None if name in listed else ("special_attribute", name)
    found = name in REFLECTIVE_PRIVATES or name in _RUNNER_PRIVATES
    return ("special_attribute", name) if found else None


def _format_finding(node: ast.Attribute, scope: _Scope) -> Optional[_Finding]:
    """The finding for a format or format_map on a template that is not fixed."""
    if node.attr not in _FORMAT_METHODS or _fixed_template(node.value, scope):
        return None
    return ("dynamic_lookup", node.attr)


def _fixed_template(expr: ast.AST, scope: _Scope) -> bool:
    """Whether ``expr`` is a string written in the code whose format fields
    read no attribute, or a name bound only to such strings."""
    if not isinstance(expr, ast.Name):
        return _fixed_string(expr)
    # A builtin's name falls back to the builtin until the code binds it
    # (str.format before str = "...").
    if expr.id in _ALL_BUILTIN_NAMES or scope.star:
        return False
    if expr.id not in scope.templates:
        sites = scope.sites.get(expr.id, [])
        scope.templates[expr.id] = bool(sites) and all(
            _fixed_string(_assigned_value(site, scope)) for site in sites
        )
    return scope.templates[expr.id]


def _fixed_string(expr: ast.AST) -> bool:
    """Whether ``expr`` is a string constant whose fields read no attribute."""
    return isinstance(expr, ast.Constant) and isinstance(expr.value, str) and _reads_no_attribute(expr.value)


def _assigned_value(site: ast.AST, scope: _Scope) -> ast.AST:
    """The value a plain ``name = value`` assigns at ``site``, else ``site``
    (which is then not a string constant)."""
    parent = scope.parents.get(id(site))
    if isinstance(parent, ast.Assign) and site in parent.targets:
        return parent.value
    if isinstance(parent, ast.AnnAssign) and parent.target is site and parent.value is not None:
        return parent.value
    return site


def _reads_no_attribute(template: str) -> bool:
    """Whether no field of ``template``, nested ones included, names an
    attribute ("{0.x}"); a template Python would not parse is refused."""
    pending = [(template, 0)]
    while pending:
        text, depth = pending.pop()
        if depth > _MAX_FORMAT_NESTING:
            return False
        try:
            fields = list(_FORMATTER.parse(text))
        except ValueError:
            return False
        for _, field, spec, _ in fields:
            if field is not None and "." in field:
                return False
            if spec:
                pending.append((spec, depth + 1))
    return True


def _class_pattern_finding(node: ast.MatchClass, scope: _Scope) -> Optional[_Finding]:
    """The finding for positional parts in a pattern on a class that is not static."""
    if not node.patterns or _static_class(node.cls, scope, scope.static):
        return None
    return ("dynamic_lookup", _dotted_name(node.cls) or "class pattern")


def _static_class(expr: ast.AST, scope: _Scope, classes: Set[str]) -> bool:
    """Whether ``expr`` names a class whose attributes code cannot have set
    at run time: a listed one (through an import), a builtin the code does
    not rebind, or one of ``classes``. (A builtin that is not a class, such
    as print, fails at run time as a class pattern or a base.)"""
    if isinstance(expr, ast.Subscript):
        expr = expr.value  # Generic[T] is based on Generic
    dotted = _dotted_name(expr)
    if dotted is None:
        return False
    head, _, rest = dotted.partition(".")
    if scope.import_bound(head):
        return True
    if rest or scope.star:
        return False
    return head in classes or (head in ADMITTED_BUILTINS and head not in scope.sites)


def _settle_classes(scope: _Scope) -> Tuple[Set[str], Set[str]]:
    """The names of the class statements whose bases and metaclass are
    static, whose decorators are listed names, and whose __match_args__ is
    a literal tuple of names (static); and of those whose bases also hold
    no reflective private (safe). One pass in source order: a base defined
    later in the source does not count, which keeps the check linear."""
    static: Set[str] = set()
    safe: Set[str] = set()
    classes = sorted(
        (node for node in scope.nodes if isinstance(node, ast.ClassDef) and scope.bound_only_by(node.name, node)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for cls in classes:
        if _class_is_static(cls, scope, static):
            static.add(cls.name)
            if _bases_are_safe(cls, scope, safe):
                safe.add(cls.name)
    return static, safe


def _class_parents(cls: ast.ClassDef) -> List[ast.AST]:
    """The bases and metaclass of ``cls``."""
    return list(cls.bases) + _metaclasses(cls)


def _metaclasses(cls: ast.ClassDef) -> List[ast.AST]:
    """The metaclass ``cls`` names, if any."""
    return [keyword.value for keyword in cls.keywords if keyword.arg == "metaclass"]


def _class_is_static(cls: ast.ClassDef, scope: _Scope, static: Set[str]) -> bool:
    """Whether code cannot have set ``cls``'s __match_args__ at run time."""
    # A metaclass of the code's own can set __match_args__ in the namespace
    # it builds (ns["__match_args__"] = ...) and answer isinstance for any
    # object, so only a listed or builtin metaclass keeps a class static.
    return (
        all(_static_class(base, scope, static) for base in cls.bases)
        and all(_static_class(meta, scope, set()) for meta in _metaclasses(cls))
        and all(scope.import_bound(_head(decorator)) for decorator in cls.decorator_list)
        and all(_literal_names(site, scope) for site in ast.walk(cls) if "__match_args__" in _bound_names(site))
    )


def _head(decorator: ast.AST) -> str:
    """The first name of a decorator's dotted name (dataclasses for
    @dataclasses.dataclass(...)), or "" when it has none."""
    dotted = _dotted_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
    return dotted.partition(".")[0] if dotted else ""


def _literal_names(site: ast.AST, scope: _Scope) -> bool:
    """Whether ``site`` assigns a literal tuple or list of plain attribute
    names (__match_args__ = ("x", "y"))."""
    value = _assigned_value(site, scope)
    return isinstance(value, (ast.Tuple, ast.List)) and all(
        isinstance(item, ast.Constant) and isinstance(item.value, str) and item.value.isidentifier()
        and _special_name_finding(item.value, False) is None
        for item in value.elts
    )


def _bases_are_safe(cls: ast.ClassDef, scope: _Scope, safe: Set[str]) -> bool:
    """Whether each base and the metaclass of ``cls`` is a builtin, one of
    the ``safe`` class statements, or a listed class that holds no
    reflective private, nor does its metaclass (Enum's metaclass holds
    _convert_)."""
    for parent in _class_parents(cls):
        if isinstance(parent, ast.Subscript):
            parent = parent.value
        dotted = _dotted_name(parent)
        if dotted and scope.import_bound(dotted.partition(".")[0]):
            if any(_holds_reflective_private(target) for target in _chain_targets(parent, scope.bindings)):
                return False
        elif not _static_class(parent, scope, safe):
            return False
    return True


def _holds_reflective_private(target: str) -> bool:
    """Whether the dotted name ``target`` may be a class that, or whose
    metaclass, defines a name in REFLECTIVE_PRIVATES: one of
    CLASSES_WITH_REFLECTIVE_PRIVATES, or any name that is not listed
    directly in a listed module (a trusted module's, or a nested one)."""
    module, _, name = target.rpartition(".")
    if name not in ADMITTED_MODULES.get(module, ()):
        return True
    return target in CLASSES_WITH_REFLECTIVE_PRIVATES


def _is_dataclass(cls: ast.ClassDef, scope: _Scope) -> bool:
    """Whether a decorator of ``cls`` is dataclasses.dataclass."""
    return any(
        "dataclasses.dataclass" in _chain_targets(
            decorator.func if isinstance(decorator, ast.Call) else decorator, scope.bindings
        )
        for decorator in cls.decorator_list
    )


def _decorator_only_finding(node: ast.AST, targets: List[str], scope: _Scope) -> Optional[_Finding]:
    """The finding for a use of a DECORATOR_ONLY name, among the dotted
    names ``node`` can stand for, other than as the decorator it is
    admitted as."""
    for target in targets:
        owners = DECORATOR_ONLY.get(target)
        if owners and not _decorates(node, target, owners, scope):
            return ("dynamic_lookup", target)
    return None


def _decorates(node: ast.AST, target: str, owners: Tuple[type, ...], scope: _Scope) -> bool:
    """Whether ``node`` (naming ``target``) is used as the decorator it is
    admitted as, on one of ``owners``."""
    owner, call = scope.decorations.get(id(node), (None, None))
    if not isinstance(owner, owners):
        return False
    if target == "functools.wraps":
        # wraps(f): one function, no names to copy.
        return call is not None and len(call.args) == 1 and not call.keywords and not isinstance(
            call.args[0], ast.Starred
        )
    # dataclass or dataclass(frozen=True, ...), on a class with safe bases.
    return (call is None or not call.args) and _bases_are_safe(owner, scope, scope.safe)


def _import_bindings(
    nodes: List[ast.AST], trusted: FrozenSet[str], found: Dict
) -> Dict[str, Set[str]]:
    """Each name an admitted import binds, mapped to every dotted name it is
    bound to (a module, or a listed name in one). Imports the lists do not
    admit are findings and bind nothing here."""
    bindings: Dict[str, Set[str]] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            _bind_import(node, trusted, found, bindings)
        elif isinstance(node, ast.ImportFrom):
            _bind_from_import(node, trusted, found, bindings)
    return bindings


def _bind_import(node: ast.Import, trusted: FrozenSet[str], found: Dict, bindings: Dict) -> None:
    """Bind the names ``import a.b as c`` binds, or add a finding."""
    for alias in node.names:
        if not _module_admitted(alias.name, trusted):
            _add(found, ("module_not_admitted", alias.name), node.lineno)
        elif alias.asname:
            bindings.setdefault(alias.asname, set()).add(alias.name)
        else:
            # import os.path binds os.
            top = alias.name.split(".")[0]
            bindings.setdefault(top, set()).add(top)


def _bind_from_import(node: ast.ImportFrom, trusted: FrozenSet[str], found: Dict, bindings: Dict) -> None:
    """Bind the names ``from m import x as y`` binds, or add a finding."""
    module = node.module or ""
    if node.level:
        # Relative to a package this check cannot see.
        _add(found, ("module_not_admitted", "." * node.level + module), node.lineno)
        return
    if not _module_admitted(module, trusted):
        _add(found, ("module_not_admitted", module), node.lineno)
        return
    is_trusted = module.split(".")[0] in trusted
    for alias in node.names:
        target = f"{module}.{alias.name}"
        if alias.name == "*":
            if not is_trusted and module not in STAR_IMPORT_MODULES:
                _add(found, ("attribute_not_admitted", target), node.lineno)
            continue
        if not is_trusted and target not in ADMITTED_MODULES and alias.name not in ADMITTED_MODULES[module]:
            _add(found, ("attribute_not_admitted", target), node.lineno)
            continue
        bindings.setdefault(alias.asname or alias.name, set()).add(target)


def _module_admitted(path: str, trusted: FrozenSet[str]) -> bool:
    """Whether module ``path`` is listed or under a trusted top-level name."""
    return path.split(".")[0] in trusted or path in ADMITTED_MODULES


def _chain_finding(node: ast.AST, targets: List[str], trusted: FrozenSet[str]) -> Optional[_Finding]:
    """The finding for a Name or attribute chain whose head an import binds,
    given the dotted names it can stand for (_chain_targets)."""
    for target in targets:
        finding = _module_use(target, node.ctx, trusted)
        if finding:
            return finding
    return None


def _chain_targets(node: ast.AST, bindings: Dict[str, Set[str]]) -> List[str]:
    """Each dotted name a Name or attribute chain whose head an import binds
    can stand for (json.dumps for d.dumps after import json as d)."""
    if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
        return []  # binding the name again is not a use of the module
    dotted = _dotted_name(node)
    if dotted is None:
        return []
    head, _, rest = dotted.partition(".")
    return [target + ("." + rest if rest else "") for target in sorted(bindings.get(head, ()))]


def _module_use(dotted: str, ctx: ast.AST, trusted: FrozenSet[str]) -> Optional[_Finding]:
    """The finding for a use of ``dotted``, which starts at an admitted
    module: one of its listed names read is admitted; the module itself, a
    name not listed for it, or a write into it is not."""
    parts = dotted.split(".")
    if parts[0] in trusted:
        return None
    depth = 1
    while depth < len(parts) and ".".join(parts[: depth + 1]) in ADMITTED_MODULES:
        depth += 1
    module = ".".join(parts[:depth])
    if module not in ADMITTED_MODULES:
        return ("module_not_admitted", module)
    if depth == len(parts):
        return ("module_reference", module) if isinstance(ctx, ast.Load) else ("module_write", dotted)
    if parts[depth] not in ADMITTED_MODULES[module]:
        return ("attribute_not_admitted", f"{module}.{parts[depth]}")
    if not isinstance(ctx, ast.Load):
        return ("module_write", dotted)
    return None


def _dotted_name(node: ast.AST) -> Optional[str]:
    """``a.b.c`` for a Name/Attribute chain, else None."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _add(found: Dict, finding: _Finding, line: Optional[int]) -> None:
    """Record ``finding`` at ``line`` once, as a CodeVerifier issue."""
    issue_type, pattern = finding
    found.setdefault((issue_type, pattern, line), {
        "severity": "CRITICAL",
        "issue_type": issue_type,
        "pattern": pattern,
        "description": _DESCRIPTIONS[issue_type],
        "line_number": line,
        "recommendation": _RECOMMENDATION,
    })
