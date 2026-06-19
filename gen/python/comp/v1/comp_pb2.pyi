from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AuthMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUTH_METHOD_USER_AGENT: _ClassVar[AuthMethod]
    AUTH_METHOD_IP: _ClassVar[AuthMethod]
    AUTH_METHOD_TOKEN: _ClassVar[AuthMethod]
    AUTH_METHOD_WEBBOT: _ClassVar[AuthMethod]
    AUTH_METHOD_AGENT_ID: _ClassVar[AuthMethod]
    AUTH_METHOD_OTHER: _ClassVar[AuthMethod]

class ScopeType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCOPE_TYPE_FULL_CORPUS: _ClassVar[ScopeType]
    SCOPE_TYPE_SECTION: _ClassVar[ScopeType]
    SCOPE_TYPE_DATE_RANGE: _ClassVar[ScopeType]
    SCOPE_TYPE_GENRE: _ClassVar[ScopeType]
    SCOPE_TYPE_TOPIC: _ClassVar[ScopeType]
    SCOPE_TYPE_CURATED: _ClassVar[ScopeType]
    SCOPE_TYPE_OTHER: _ClassVar[ScopeType]

class Function(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FUNCTION_ALL: _ClassVar[Function]
    FUNCTION_AI_ALL: _ClassVar[Function]
    FUNCTION_AI_TRAIN: _ClassVar[Function]
    FUNCTION_AI_INPUT: _ClassVar[Function]
    FUNCTION_AI_INDEX: _ClassVar[Function]
    FUNCTION_SEARCH: _ClassVar[Function]

class SubFunction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SUB_FUNCTION_TRAINING: _ClassVar[SubFunction]
    SUB_FUNCTION_RAG: _ClassVar[SubFunction]
    SUB_FUNCTION_GROUNDING: _ClassVar[SubFunction]
    SUB_FUNCTION_AGENT_VIEW: _ClassVar[SubFunction]
    SUB_FUNCTION_AGENT_ACTIONS: _ClassVar[SubFunction]
    SUB_FUNCTION_OTHER: _ClassVar[SubFunction]

class LicenseUse(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LICENSE_USE_TRAINING_DISPLAY: _ClassVar[LicenseUse]
    LICENSE_USE_RAG_DISPLAY_UNRESTRICTED: _ClassVar[LicenseUse]
    LICENSE_USE_RAG_DISPLAY_MAX_WORDS: _ClassVar[LicenseUse]
    LICENSE_USE_RAG_DISPLAY_ATTRIBUTION: _ClassVar[LicenseUse]
    LICENSE_USE_RAG_NO_DISPLAY: _ClassVar[LicenseUse]
    LICENSE_USE_AGENT_VIEW: _ClassVar[LicenseUse]
    LICENSE_USE_AGENT_ACTIONS: _ClassVar[LicenseUse]

class ContentType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONTENT_TYPE_TEXT: _ClassVar[ContentType]
    CONTENT_TYPE_VIDEO: _ClassVar[ContentType]
    CONTENT_TYPE_IMAGE: _ClassVar[ContentType]
    CONTENT_TYPE_AUDIO: _ClassVar[ContentType]
    CONTENT_TYPE_ALL: _ClassVar[ContentType]
    CONTENT_TYPE_OTHER: _ClassVar[ContentType]

class RetrievalAuth(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RETRIEVAL_AUTH_NONE: _ClassVar[RetrievalAuth]
    RETRIEVAL_AUTH_API_KEY: _ClassVar[RetrievalAuth]
    RETRIEVAL_AUTH_OAUTH2: _ClassVar[RetrievalAuth]
    RETRIEVAL_AUTH_SSL: _ClassVar[RetrievalAuth]

class RetrievalType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RETRIEVAL_TYPE_HTML: _ClassVar[RetrievalType]
    RETRIEVAL_TYPE_RSS: _ClassVar[RetrievalType]
    RETRIEVAL_TYPE_API: _ClassVar[RetrievalType]
    RETRIEVAL_TYPE_MCP: _ClassVar[RetrievalType]
    RETRIEVAL_TYPE_NLWEB: _ClassVar[RetrievalType]
    RETRIEVAL_TYPE_XML: _ClassVar[RetrievalType]
    RETRIEVAL_TYPE_NEWSML: _ClassVar[RetrievalType]
    RETRIEVAL_TYPE_OTHER: _ClassVar[RetrievalType]
AUTH_METHOD_USER_AGENT: AuthMethod
AUTH_METHOD_IP: AuthMethod
AUTH_METHOD_TOKEN: AuthMethod
AUTH_METHOD_WEBBOT: AuthMethod
AUTH_METHOD_AGENT_ID: AuthMethod
AUTH_METHOD_OTHER: AuthMethod
SCOPE_TYPE_FULL_CORPUS: ScopeType
SCOPE_TYPE_SECTION: ScopeType
SCOPE_TYPE_DATE_RANGE: ScopeType
SCOPE_TYPE_GENRE: ScopeType
SCOPE_TYPE_TOPIC: ScopeType
SCOPE_TYPE_CURATED: ScopeType
SCOPE_TYPE_OTHER: ScopeType
FUNCTION_ALL: Function
FUNCTION_AI_ALL: Function
FUNCTION_AI_TRAIN: Function
FUNCTION_AI_INPUT: Function
FUNCTION_AI_INDEX: Function
FUNCTION_SEARCH: Function
SUB_FUNCTION_TRAINING: SubFunction
SUB_FUNCTION_RAG: SubFunction
SUB_FUNCTION_GROUNDING: SubFunction
SUB_FUNCTION_AGENT_VIEW: SubFunction
SUB_FUNCTION_AGENT_ACTIONS: SubFunction
SUB_FUNCTION_OTHER: SubFunction
LICENSE_USE_TRAINING_DISPLAY: LicenseUse
LICENSE_USE_RAG_DISPLAY_UNRESTRICTED: LicenseUse
LICENSE_USE_RAG_DISPLAY_MAX_WORDS: LicenseUse
LICENSE_USE_RAG_DISPLAY_ATTRIBUTION: LicenseUse
LICENSE_USE_RAG_NO_DISPLAY: LicenseUse
LICENSE_USE_AGENT_VIEW: LicenseUse
LICENSE_USE_AGENT_ACTIONS: LicenseUse
CONTENT_TYPE_TEXT: ContentType
CONTENT_TYPE_VIDEO: ContentType
CONTENT_TYPE_IMAGE: ContentType
CONTENT_TYPE_AUDIO: ContentType
CONTENT_TYPE_ALL: ContentType
CONTENT_TYPE_OTHER: ContentType
RETRIEVAL_AUTH_NONE: RetrievalAuth
RETRIEVAL_AUTH_API_KEY: RetrievalAuth
RETRIEVAL_AUTH_OAUTH2: RetrievalAuth
RETRIEVAL_AUTH_SSL: RetrievalAuth
RETRIEVAL_TYPE_HTML: RetrievalType
RETRIEVAL_TYPE_RSS: RetrievalType
RETRIEVAL_TYPE_API: RetrievalType
RETRIEVAL_TYPE_MCP: RetrievalType
RETRIEVAL_TYPE_NLWEB: RetrievalType
RETRIEVAL_TYPE_XML: RetrievalType
RETRIEVAL_TYPE_NEWSML: RetrievalType
RETRIEVAL_TYPE_OTHER: RetrievalType

class AISystem(_message.Message):
    __slots__ = ("name", "ua", "id", "aisysuse", "ext")
    NAME_FIELD_NUMBER: _ClassVar[int]
    UA_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    AISYSUSE_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    name: str
    ua: str
    id: str
    aisysuse: AISystemUse
    ext: _struct_pb2.Struct
    def __init__(self, name: _Optional[str] = ..., ua: _Optional[str] = ..., id: _Optional[str] = ..., aisysuse: _Optional[_Union[AISystemUse, _Mapping]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class AISystemUse(_message.Message):
    __slots__ = ("lid", "aiauth", "uri", "scope", "function", "subfn", "resdis", "ext")
    LID_FIELD_NUMBER: _ClassVar[int]
    AIAUTH_FIELD_NUMBER: _ClassVar[int]
    URI_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    SUBFN_FIELD_NUMBER: _ClassVar[int]
    RESDIS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    lid: str
    aiauth: AuthMethod
    uri: _containers.RepeatedScalarFieldContainer[str]
    scope: ScopeType
    function: _containers.RepeatedScalarFieldContainer[Function]
    subfn: _containers.RepeatedScalarFieldContainer[SubFunction]
    resdis: int
    ext: _struct_pb2.Struct
    def __init__(self, lid: _Optional[str] = ..., aiauth: _Optional[_Union[AuthMethod, str]] = ..., uri: _Optional[_Iterable[str]] = ..., scope: _Optional[_Union[ScopeType, str]] = ..., function: _Optional[_Iterable[_Union[Function, str]]] = ..., subfn: _Optional[_Iterable[_Union[SubFunction, str]]] = ..., resdis: _Optional[int] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class Package(_message.Message):
    __slots__ = ("id", "title", "seller", "packager", "licenseurl", "citation", "scope", "retrieval", "license", "ext")
    ID_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    SELLER_FIELD_NUMBER: _ClassVar[int]
    PACKAGER_FIELD_NUMBER: _ClassVar[int]
    LICENSEURL_FIELD_NUMBER: _ClassVar[int]
    CITATION_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    RETRIEVAL_FIELD_NUMBER: _ClassVar[int]
    LICENSE_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    id: str
    title: str
    seller: str
    packager: str
    licenseurl: str
    citation: int
    scope: Scope
    retrieval: Retrieval
    license: _containers.RepeatedCompositeFieldContainer[License]
    ext: _struct_pb2.Struct
    def __init__(self, id: _Optional[str] = ..., title: _Optional[str] = ..., seller: _Optional[str] = ..., packager: _Optional[str] = ..., licenseurl: _Optional[str] = ..., citation: _Optional[int] = ..., scope: _Optional[_Union[Scope, _Mapping]] = ..., retrieval: _Optional[_Union[Retrieval, _Mapping]] = ..., license: _Optional[_Iterable[_Union[License, _Mapping]]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class License(_message.Message):
    __slots__ = ("id", "turl", "use", "country", "maxword", "citation", "price", "revshare", "cur", "dur", "ext")
    ID_FIELD_NUMBER: _ClassVar[int]
    TURL_FIELD_NUMBER: _ClassVar[int]
    USE_FIELD_NUMBER: _ClassVar[int]
    COUNTRY_FIELD_NUMBER: _ClassVar[int]
    MAXWORD_FIELD_NUMBER: _ClassVar[int]
    CITATION_FIELD_NUMBER: _ClassVar[int]
    PRICE_FIELD_NUMBER: _ClassVar[int]
    REVSHARE_FIELD_NUMBER: _ClassVar[int]
    CUR_FIELD_NUMBER: _ClassVar[int]
    DUR_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    id: str
    turl: str
    use: _containers.RepeatedScalarFieldContainer[LicenseUse]
    country: _containers.RepeatedScalarFieldContainer[str]
    maxword: int
    citation: int
    price: float
    revshare: float
    cur: str
    dur: int
    ext: _struct_pb2.Struct
    def __init__(self, id: _Optional[str] = ..., turl: _Optional[str] = ..., use: _Optional[_Iterable[_Union[LicenseUse, str]]] = ..., country: _Optional[_Iterable[str]] = ..., maxword: _Optional[int] = ..., citation: _Optional[int] = ..., price: _Optional[float] = ..., revshare: _Optional[float] = ..., cur: _Optional[str] = ..., dur: _Optional[int] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class Scope(_message.Message):
    __slots__ = ("scope", "max", "ctype", "text", "video", "image", "audio", "ext")
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    MAX_FIELD_NUMBER: _ClassVar[int]
    CTYPE_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    VIDEO_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    AUDIO_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    scope: ScopeType
    max: int
    ctype: _containers.RepeatedScalarFieldContainer[ContentType]
    text: _containers.RepeatedCompositeFieldContainer[Text]
    video: _containers.RepeatedCompositeFieldContainer[Video]
    image: _containers.RepeatedCompositeFieldContainer[Image]
    audio: _containers.RepeatedCompositeFieldContainer[Audio]
    ext: _struct_pb2.Struct
    def __init__(self, scope: _Optional[_Union[ScopeType, str]] = ..., max: _Optional[int] = ..., ctype: _Optional[_Iterable[_Union[ContentType, str]]] = ..., text: _Optional[_Iterable[_Union[Text, _Mapping]]] = ..., video: _Optional[_Iterable[_Union[Video, _Mapping]]] = ..., image: _Optional[_Iterable[_Union[Image, _Mapping]]] = ..., audio: _Optional[_Iterable[_Union[Audio, _Mapping]]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class Text(_message.Message):
    __slots__ = ("title", "wordcount", "pubdate", "published", "update", "author", "sourcetype", "provenance", "provent", "authority", "originality", "ext")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    WORDCOUNT_FIELD_NUMBER: _ClassVar[int]
    PUBDATE_FIELD_NUMBER: _ClassVar[int]
    PUBLISHED_FIELD_NUMBER: _ClassVar[int]
    UPDATE_FIELD_NUMBER: _ClassVar[int]
    AUTHOR_FIELD_NUMBER: _ClassVar[int]
    SOURCETYPE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    PROVENT_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_FIELD_NUMBER: _ClassVar[int]
    ORIGINALITY_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    title: str
    wordcount: _containers.RepeatedScalarFieldContainer[int]
    pubdate: str
    published: int
    update: str
    author: _containers.RepeatedScalarFieldContainer[str]
    sourcetype: int
    provenance: int
    provent: str
    authority: float
    originality: float
    ext: _struct_pb2.Struct
    def __init__(self, title: _Optional[str] = ..., wordcount: _Optional[_Iterable[int]] = ..., pubdate: _Optional[str] = ..., published: _Optional[int] = ..., update: _Optional[str] = ..., author: _Optional[_Iterable[str]] = ..., sourcetype: _Optional[int] = ..., provenance: _Optional[int] = ..., provent: _Optional[str] = ..., authority: _Optional[float] = ..., originality: _Optional[float] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class Video(_message.Message):
    __slots__ = ("title", "dur", "clip", "wordcount", "transcript", "pubdate", "published", "update", "author", "sourcetype", "provenance", "provent", "c2pa", "ext")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    DUR_FIELD_NUMBER: _ClassVar[int]
    CLIP_FIELD_NUMBER: _ClassVar[int]
    WORDCOUNT_FIELD_NUMBER: _ClassVar[int]
    TRANSCRIPT_FIELD_NUMBER: _ClassVar[int]
    PUBDATE_FIELD_NUMBER: _ClassVar[int]
    PUBLISHED_FIELD_NUMBER: _ClassVar[int]
    UPDATE_FIELD_NUMBER: _ClassVar[int]
    AUTHOR_FIELD_NUMBER: _ClassVar[int]
    SOURCETYPE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    PROVENT_FIELD_NUMBER: _ClassVar[int]
    C2PA_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    title: _containers.RepeatedScalarFieldContainer[str]
    dur: _containers.RepeatedScalarFieldContainer[int]
    clip: int
    wordcount: _containers.RepeatedScalarFieldContainer[int]
    transcript: int
    pubdate: str
    published: int
    update: str
    author: _containers.RepeatedScalarFieldContainer[str]
    sourcetype: int
    provenance: int
    provent: str
    c2pa: str
    ext: _struct_pb2.Struct
    def __init__(self, title: _Optional[_Iterable[str]] = ..., dur: _Optional[_Iterable[int]] = ..., clip: _Optional[int] = ..., wordcount: _Optional[_Iterable[int]] = ..., transcript: _Optional[int] = ..., pubdate: _Optional[str] = ..., published: _Optional[int] = ..., update: _Optional[str] = ..., author: _Optional[_Iterable[str]] = ..., sourcetype: _Optional[int] = ..., provenance: _Optional[int] = ..., provent: _Optional[str] = ..., c2pa: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class Image(_message.Message):
    __slots__ = ("title", "pubdate", "published", "update", "author", "sourcetype", "provenance", "provent", "alt", "caption", "c2pa", "ext")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    PUBDATE_FIELD_NUMBER: _ClassVar[int]
    PUBLISHED_FIELD_NUMBER: _ClassVar[int]
    UPDATE_FIELD_NUMBER: _ClassVar[int]
    AUTHOR_FIELD_NUMBER: _ClassVar[int]
    SOURCETYPE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    PROVENT_FIELD_NUMBER: _ClassVar[int]
    ALT_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    C2PA_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    title: _containers.RepeatedScalarFieldContainer[str]
    pubdate: str
    published: int
    update: str
    author: _containers.RepeatedScalarFieldContainer[str]
    sourcetype: int
    provenance: int
    provent: str
    alt: str
    caption: str
    c2pa: str
    ext: _struct_pb2.Struct
    def __init__(self, title: _Optional[_Iterable[str]] = ..., pubdate: _Optional[str] = ..., published: _Optional[int] = ..., update: _Optional[str] = ..., author: _Optional[_Iterable[str]] = ..., sourcetype: _Optional[int] = ..., provenance: _Optional[int] = ..., provent: _Optional[str] = ..., alt: _Optional[str] = ..., caption: _Optional[str] = ..., c2pa: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class Audio(_message.Message):
    __slots__ = ("title", "dur", "wordcount", "transcript", "pubdate", "published", "update", "author", "sourcetype", "provenance", "provent", "c2pa", "ext")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    DUR_FIELD_NUMBER: _ClassVar[int]
    WORDCOUNT_FIELD_NUMBER: _ClassVar[int]
    TRANSCRIPT_FIELD_NUMBER: _ClassVar[int]
    PUBDATE_FIELD_NUMBER: _ClassVar[int]
    PUBLISHED_FIELD_NUMBER: _ClassVar[int]
    UPDATE_FIELD_NUMBER: _ClassVar[int]
    AUTHOR_FIELD_NUMBER: _ClassVar[int]
    SOURCETYPE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    PROVENT_FIELD_NUMBER: _ClassVar[int]
    C2PA_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    title: _containers.RepeatedScalarFieldContainer[str]
    dur: _containers.RepeatedScalarFieldContainer[int]
    wordcount: _containers.RepeatedScalarFieldContainer[int]
    transcript: int
    pubdate: str
    published: int
    update: str
    author: _containers.RepeatedScalarFieldContainer[str]
    sourcetype: int
    provenance: int
    provent: str
    c2pa: str
    ext: _struct_pb2.Struct
    def __init__(self, title: _Optional[_Iterable[str]] = ..., dur: _Optional[_Iterable[int]] = ..., wordcount: _Optional[_Iterable[int]] = ..., transcript: _Optional[int] = ..., pubdate: _Optional[str] = ..., published: _Optional[int] = ..., update: _Optional[str] = ..., author: _Optional[_Iterable[str]] = ..., sourcetype: _Optional[int] = ..., provenance: _Optional[int] = ..., provent: _Optional[str] = ..., c2pa: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class Retrieval(_message.Message):
    __slots__ = ("auth", "endpoint", "type", "ratelmt", "ext")
    AUTH_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    RATELMT_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    auth: RetrievalAuth
    endpoint: str
    type: _containers.RepeatedScalarFieldContainer[RetrievalType]
    ratelmt: int
    ext: _struct_pb2.Struct
    def __init__(self, auth: _Optional[_Union[RetrievalAuth, str]] = ..., endpoint: _Optional[str] = ..., type: _Optional[_Iterable[_Union[RetrievalType, str]]] = ..., ratelmt: _Optional[int] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...
