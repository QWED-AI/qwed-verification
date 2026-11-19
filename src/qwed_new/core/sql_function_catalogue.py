"""
The functions sqlglot parses into a known expression, as of sqlglot 28.0.0
and 30.31.0, sorted into those that stay inside the database and those that
reach outside it (GHSA-wgcp-398q-m296).

SQLVerifier and SQLGuard admit a function sqlglot knows only when its kind
is in ``TYPED_FUNCTIONS``. A kind a later sqlglot adds is not, so it is
refused until someone reads what it does and adds it here. ``AI.GENERATE``,
``ML.PREDICT``, ``secret()`` and ``read_csv`` show why: a new kind can send
data to a model, read a secret or read a file.

Kinds are ``Expression.key``: the class name in lower case.
"""

# Kinds that read files, stages or secrets, send data to a model, build a
# name from a string, or advance a sequence.
REACHING_TYPED_FUNCTIONS = frozenset({
    "aiagg", "aiclassify", "aiembed", "aiforecast", "aigenerate", "aisimilarity",
    "aisummarizeagg", "dynamicidentifier", "generatebool", "generatedouble",
    "generateembedding", "generateint", "generatetable", "generatetext", "mlforecast",
    "mltranslate", "nextvaluefor", "predict", "readcsv", "readparquet", "secret", "tofile",
    "vectorsearch"
})

# Every other kind of the two versions.
TYPED_FUNCTIONS = frozenset({
    "_explodeouter", "abs", "acos", "acosh", "addmonths", "agg", "aggfunc", "and",
    "anonymousaggfunc", "anyvalue", "apply", "approxdistinct", "approximatesimilarity",
    "approxpercentileaccumulate", "approxpercentilecombine", "approxpercentileestimate",
    "approxquantile", "approxquantiles", "approxtopk", "approxtopkaccumulate",
    "approxtopkcombine", "approxtopkestimate", "approxtopsum", "argmax", "argmin", "array",
    "arrayagg", "arrayall", "arrayany", "arrayappend", "arraycompact", "arrayconcat",
    "arrayconcatagg", "arrayconstructcompact", "arraycontainedby", "arraycontains",
    "arraycontainsall", "arraydistinct", "arrayexcept", "arrayfilter", "arrayfirst",
    "arrayinsert", "arrayintersect", "arraylast", "arraymax", "arraymin", "arrayoverlaps",
    "arrayposition", "arrayprepend", "arrayremove", "arrayremoveat", "arrayreverse",
    "arraysize", "arrayslice", "arraysort", "arraysum", "arrayszip", "arraytostring",
    "arrayunionagg", "arrayuniqueagg", "ascii", "asin", "asinh", "atan", "atan2", "atanh",
    "avg", "base64decodebinary", "base64decodestring", "base64encode", "bitlength",
    "bitmapbitposition", "bitmapbucketnumber", "bitmapconstructagg", "bitmapcount",
    "bitmaporagg", "bitwiseandagg", "bitwisecount", "bitwiseoragg", "bitwisexoragg", "booland",
    "boolnot", "boolor", "boolxoragg", "bytelength", "case", "cast", "casttostrtype", "cbrt",
    "ceil", "checkjson", "checkxml", "chr", "cityhash64", "coalesce", "codepointstobytes",
    "codepointstostring", "collate", "collation", "columns", "combinedaggfunc",
    "combinedparameterizedagg", "compress", "concat", "concatws", "connectbyroot", "contains",
    "convert", "converttimezone", "converttocharset", "corr", "cos", "cosh", "cosinedistance",
    "cot", "coth", "count", "countif", "covarpop", "covarsamp", "csc", "csch", "cumedist",
    "currentaccount", "currentaccountname", "currentavailableroles", "currentcatalog",
    "currentclient", "currentdatabase", "currentdate", "currentdatetime", "currentipaddress",
    "currentorganizationname", "currentorganizationuser", "currentregion", "currentrole",
    "currentroletype", "currentschema", "currentschemas", "currentsecondaryroles",
    "currentsession", "currentstatement", "currenttime", "currenttimestamp",
    "currenttimestampltz", "currenttimezone", "currenttransaction", "currentuser",
    "currentuserid", "currentversion", "currentwarehouse", "date", "dateadd", "datebin",
    "datediff", "datefromparts", "datefromunixdate", "datestrtodate", "datesub", "datetime",
    "datetimeadd", "datetimediff", "datetimesub", "datetimetrunc", "datetodatestr", "datetodi",
    "datetrunc", "day", "dayname", "dayofmonth", "dayofweek", "dayofweekiso", "dayofyear",
    "decode", "decodecase", "decompressbinary", "decompressstring", "decrypt", "decryptraw",
    "degrees", "denserank", "ditodate", "dotproduct", "elt", "encode", "encrypt", "encryptraw",
    "endswith", "equalnull", "euclideandistance", "exists", "exp", "explode", "explodeouter",
    "explodinggenerateseries", "extract", "factorial", "farmfingerprint", "featuresattime",
    "first", "firstvalue", "flatten", "float64", "floor", "format", "frombase", "frombase32",
    "frombase64", "fromiso8601date", "fromiso8601timestamp", "fromiso8601timestampnanos",
    "fromjson", "func", "gapfill", "generatedatearray", "generateseries",
    "generatetimestamparray", "generator", "getbit", "getextract", "getignorecase", "greatest",
    "greatestignorenulls", "groupconcat", "grouping", "groupingid", "hashagg", "hex",
    "hexdecodestring", "hexencode", "hll", "host", "hour", "if", "initcap", "inline", "int64",
    "isarray", "isascii", "isinf", "isnan", "isnullvalue", "jarowinklersimilarity", "jsonarray",
    "jsonarrayagg", "jsonarrayappend", "jsonarraycontains", "jsonarrayinsert", "jsonbcontains",
    "jsonbcontainsalltopkeys", "jsonbcontainsanytopkeys", "jsonbcontainstopkey",
    "jsonbdeleteatpath", "jsonbexists", "jsonbextract", "jsonbextractscalar", "jsonbobjectagg",
    "jsonbool", "jsonbpathexists", "jsoncast", "jsonexists", "jsonextract", "jsonextractarray",
    "jsonextractscalar", "jsonformat", "jsonkeys", "jsonkeysatdepth", "jsonobject",
    "jsonobjectagg", "jsonremove", "jsonset", "jsonstripnulls", "jsontable", "jsontype",
    "jsonvaluearray", "justifydays", "justifyhours", "justifyinterval", "kurtosis", "lag",
    "last", "lastday", "lastvalue", "laxbool", "laxfloat64", "laxint64", "laxstring", "lead",
    "least", "leastignorenulls", "left", "length", "levenshtein", "list", "ln", "localtime",
    "localtimestamp", "log", "logicaland", "logicalor", "lower", "lowerhex", "makeinterval",
    "manhattandistance", "map", "mapcat", "mapcontainskey", "mapdelete", "mapfromentries",
    "mapinsert", "mapkeys", "mappick", "mapsize", "matchagainst", "max", "md5", "md5digest",
    "md5numberlower64", "md5numberupper64", "median", "min", "minhash", "minhashcombine",
    "minute", "mode", "month", "monthname", "monthsbetween", "nanvl", "negative", "netfunc",
    "nextday", "normal", "normalize", "nthvalue", "ntile", "nullif", "numbertostr", "nvl2",
    "objectagg", "objectid", "objectinsert", "objecttransform", "openjson", "or", "overlay",
    "pad", "parameterizedagg", "parsebignumeric", "parsedatetime", "parseip", "parsejson",
    "parsenumeric", "parsetime", "parseurl", "percentilecont", "percentiledisc", "percentrank",
    "pi", "posexplode", "posexplodeouter", "pow", "previousday", "quantile", "quarter",
    "radians", "rand", "randn", "randstr", "rangebucket", "rangen", "rank", "reduce",
    "regdomain", "regexpcount", "regexpextract", "regexpextractall", "regexpfullmatch",
    "regexpilike", "regexpinstr", "regexplike", "regexpreplace", "regexpsplit", "regexpsubstr",
    "regravgx", "regravgy", "regrcount", "regrintercept", "regrr2", "regrslope", "regrsxx",
    "regrsxy", "regrsyy", "regrvalx", "regrvaly", "repeat", "replace", "reverse", "right",
    "rint", "round", "rownumber", "rtrimmedlength", "safeadd", "safeconvertbytestostring",
    "safedivide", "safefunc", "safemultiply", "safenegate", "safesubtract", "search",
    "searchip", "sec", "sech", "second", "seq1", "seq2", "seq4", "seq8", "sessionuser", "sha",
    "sha1digest", "sha2", "sha2digest", "shuffle", "sign", "sin", "sinh", "skewness",
    "sortarray", "soundex", "soundexp123", "space", "split", "splitpart", "splittotable",
    "sqrt", "stack", "standardhash", "starmap", "startswith", "stddev", "stddevpop",
    "stddevsamp", "stdistance", "stpoint", "string", "stringtoarray", "stripnullvalue",
    "strposition", "strtodate", "strtok", "strtoksplittotable", "strtoktoarray", "strtomap",
    "strtotime", "strtounix", "struct", "structextract", "stuff", "substring", "substringindex",
    "sum", "systimestamp", "tan", "tanh", "time", "timeadd", "timediff", "timefromparts",
    "timeslice", "timestamp", "timestampadd", "timestampdiff", "timestampfromparts",
    "timestampltzfromparts", "timestampsub", "timestamptrunc", "timestamptzfromparts",
    "timestrtodate", "timestrtotime", "timestrtounix", "timesub", "timetostr", "timetotimestr",
    "timetounix", "timetrunc", "toarray", "tobase32", "tobase64", "tobinary", "toboolean",
    "tochar", "tocodepoints", "todays", "todecfloat", "todouble", "tomap", "tonumber",
    "tovariant", "transform", "translate", "trim", "trunc", "try", "trybase64decodebinary",
    "trybase64decodestring", "trycast", "tryhexdecodebinary", "tryhexdecodestring",
    "trytodecfloat", "tsorditodi", "tsordsadd", "tsordsdiff", "tsordstodate", "tsordstodatestr",
    "tsordstodatetime", "tsordstotime", "tsordstotimestamp", "typeof", "unhex", "unicode",
    "uniform", "unixdate", "unixmicros", "unixmillis", "unixseconds", "unixtostr", "unixtotime",
    "unixtotimestr", "unnest", "upper", "utcdate", "utctime", "utctimestamp", "uuid",
    "variance", "variancepop", "varmap", "week", "weekofyear", "weekstart",
    "weightstring", "widthbucket", "xmlelement", "xmlget", "xmltable", "xor", "year",
    "yearofweek", "yearofweekiso", "zipf"
})
