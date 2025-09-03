
from __future__ import annotations
import os, re, json, base64, hashlib, hmac, copy, uuid
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional, Pattern

import yaml

try:
    import spacy
except ImportError:
    spacy = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

try:
    from ff3 import FF3Cipher  # optional format-preserving encryption
except Exception:
    FF3Cipher = None


# -----------------------------
# Config models
# -----------------------------
@dataclass
class StructuredKeyRule:
    key: Pattern
    policy: str

@dataclass
class RegexRule:
    name: str
    pattern: Pattern
    policy: str

@dataclass
class Config:
    language: str
    spacy_model: Optional[str]
    confidence_threshold: float
    use_regex: bool
    use_ner: bool
    structured_keys: List[StructuredKeyRule]
    custom_regexes: List[RegexRule]
    entity_policies: Dict[str, str]
    default_policy: str
    mask_char: str
    preserve_length: bool
    enc_algo: str
    key_id: str
    key_source: str
    aes_key: Optional[bytes]
    aad_fields: List[str]
    hash_algo: str
    hash_salt: bytes
    token_secret: bytes
    token_prefix: str
    fpe_enabled: bool
    fpe_cipher: Optional[Any]

    @staticmethod
    def from_yaml(path: str) -> "Config":
        with open(path, "r") as f:
            raw = yaml.safe_load(f)

        det = raw.get("detection", {})
        enc = raw.get("encryption", {})
        hashing = raw.get("hashing", {})
        tok = raw.get("tokenization", {})
        fpe = raw.get("fpe", {})
        out = raw.get("output", {})
        masking = raw.get("masking", {})
        models = raw.get("models", {})

        # Structured keys
        sk = []
        for r in det.get("structured_keys", []):
            sk.append(StructuredKeyRule(
                key=re.compile(r["key"]),
                policy=r["policy"].upper()
            ))

        # Custom regexes
        rx = []
        for r in det.get("custom_regexes", []):
            rx.append(RegexRule(
                name=r["name"],
                pattern=re.compile(r["pattern"]),
                policy=r["policy"].upper()
            ))

        # Keys
        aes_key = None
        if enc.get("key_source") == "ENV":
            k = os.getenv(enc.get("env_key_var", "MASKING_AES_KEY_B64"))
            if k:
                aes_key = base64.b64decode(k)

        hash_salt = base64.b64decode(os.getenv(hashing.get("salt_env_var", "MASKING_SALT_B64"), ""))
        token_secret = base64.b64decode(os.getenv(tok.get("secret_env_var", "MASKING_TOKEN_SECRET_B64"), ""))

        # FPE
        fpe_cipher = None
        if fpe.get("enabled") and FF3Cipher:
            tweak = base64.b64decode(fpe.get("tweak", "")) if fpe.get("tweak") else b""
            fpe_key_hex = os.getenv("MASKING_FPE_KEY_HEX", "")  # hex string
            if fpe_key_hex:
                try:
                    fpe_cipher = FF3Cipher.withCustomAlphabet(fpe_key_hex, tweak, "0123456789")
                except Exception:
                    fpe_cipher = None

        return Config(
            language=raw.get("language", "en"),
            spacy_model=models.get("spacy_model"),
            confidence_threshold=det.get("confidence_threshold", 0.75),
            use_regex=det.get("use_regex", True),
            use_ner=det.get("use_ner", True),
            structured_keys=sk,
            custom_regexes=rx,
            entity_policies={k.upper(): v.upper() for k, v in raw.get("entities", {}).items()},
            default_policy=masking.get("default_policy", "NONE").upper(),
            mask_char=masking.get("mask_char", "█"),
            preserve_length=masking.get("preserve_length", True),
            enc_algo=enc.get("algorithm", "AES_GCM"),
            key_id=enc.get("key_id", "default"),
            key_source=enc.get("key_source", "ENV"),
            aes_key=aes_key,
            aad_fields=enc.get("aad_fields", []),
            hash_algo=hashing.get("algo", "SHA256"),
            hash_salt=hash_salt,
            token_secret=token_secret,
            token_prefix=tok.get("prefix", "tok_"),
            fpe_enabled=fpe.get("enabled", False),
            fpe_cipher=fpe_cipher
        )


# -----------------------------
# Detection
# -----------------------------
@dataclass
class Span:
    start: int
    end: int
    label: str
    source: str  # "NER" | "REGEX"
    text: str
    score: float = 1.0
    policy: Optional[str] = None

class Detector:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.nlp = None
        if spacy and cfg.spacy_model and cfg.use_ner:
            try:
                self.nlp = spacy.load(cfg.spacy_model)
            except OSError:
                # model not installed
                self.nlp = None

    def detect_text(self, text: str) -> List[Span]:
        spans: List[Span] = []

        # 1) NER
        if self.nlp and self.cfg.use_ner:
            doc = self.nlp(text)
            for ent in doc.ents:
                label = ent.label_.upper()
                score = 1.0  # spaCy doesn't expose calibrated prob by default
                if label in self.cfg.entity_policies and score >= self.cfg.confidence_threshold:
                    spans.append(Span(ent.start_char, ent.end_char, label, "NER", ent.text, float(score)))

        # 2) Regex
        if self.cfg.use_regex:
            for rule in self.cfg.custom_regexes:
                for m in rule.pattern.finditer(text):
                    spans.append(Span(m.start(), m.end(), rule.name.upper(), "REGEX", m.group(0), 1.0, rule.policy))

        # Merge overlaps – prefer longer spans and REGEX policy if specified
        spans = self._merge_overlaps(spans)
        # Attach policies
        for s in spans:
            if s.policy:
                continue
            s.policy = self.cfg.entity_policies.get(s.label, self.cfg.default_policy)
        return [s for s in spans if s.policy and s.policy != "NONE"]

    @staticmethod
    def _merge_overlaps(spans: List[Span]) -> List[Span]:
        spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
        out: List[Span] = []
        for s in spans:
            if not out:
                out.append(s); continue
            last = out[-1]
            if s.start <= last.end:  # overlap
                # keep the longer one
                if (s.end - s.start) > (last.end - last.start):
                    out[-1] = s
                elif (s.end - s.start) == (last.end - last.start) and s.source == "REGEX":
                    out[-1] = s
            else:
                out.append(s)
        return out

    def detect_structured(self, obj: Any) -> List[Tuple[List[str], Any, str]]:
        """
        Returns matches as tuples: (path, value, policy)
        path: list of keys/indexes from root to the value
        """
        results: List[Tuple[List[str], Any, str]] = []
        def walk(node, path):
            if isinstance(node, dict):
                for k, v in node.items():
                    key_str = str(k)
                    applied = False
                    for rule in self.cfg.structured_keys:
                        if rule.key.search(key_str):
                            results.append((path + [k], v, rule.policy))
                            applied = True
                            break
                    if not applied:
                        walk(v, path + [k])
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, path + [i])
        walk(obj, [])
        return results


# -----------------------------
# Transformers (Policies)
# -----------------------------
class Transformer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._token_cache: Dict[str, str] = {}

    def apply_policy_text(self, text: str, spans: List[Span], context: Dict[str, str]) -> Tuple[str, Dict[str, str]]:
        """
        Apply masking in text; returns masked_text and replacement_map
        """
        repl_map: Dict[str, str] = {}
        out: List[str] = []
        cursor = 0
        for s in sorted(spans, key=lambda x: x.start):
            out.append(text[cursor:s.start])
            original = text[s.start:s.end]
            masked, token = self._mask_value(original, s.policy, context)
            out.append(masked)
            if token:
                repl_map[token] = original
            cursor = s.end
        out.append(text[cursor:])
        return "".join(out), repl_map

    def apply_policy_structured(self, obj: Any, matches: List[Tuple[List[str], Any, str]], context: Dict[str, str]) -> Tuple[Any, Dict[str, str]]:
        out = json.loads(json.dumps(obj))  # cheap deep copy preserving types
        repl_map: Dict[str, str] = {}
        for path, value, policy in matches:
            original_str = json.dumps(value, ensure_ascii=False) if not isinstance(value, (str, int, float)) else str(value)
            masked, token = self._mask_value(original_str, policy, context)
            # Set back
            ref = out
            for p in path[:-1]:
                ref = ref[p]
            ref[path[-1]] = masked
            if token:
                repl_map[token] = original_str
        return out, repl_map

    # --- individual policies
    def _mask_value(self, s: str, policy: str, context: Dict[str, str]) -> Tuple[str, Optional[str]]:
        policy = policy.upper()
        if policy == "REDACT":
            return self._redact(s), None
        elif policy == "HASH":
            return self._hash(s), None
        elif policy == "ENCRYPT":
            return self._encrypt(s, context), None
        elif policy == "FPE" and self.cfg.fpe_enabled and self.cfg.fpe_cipher:
            return self._fpe(s), None
        elif policy == "TOKENIZE":
            tok = self._tokenize(s)
            return tok, tok  # token used as key in repl_map
        else:
            return s, None

    def _redact(self, s: str) -> str:
        if self.cfg.preserve_length:
            return self.cfg.mask_char * len(s)
        return self.cfg.mask_char * min(8, max(4, len(s)//2))

    def _hash(self, s: str) -> str:
        h = hashlib.sha256()
        if self.cfg.hash_salt:
            h.update(self.cfg.hash_salt)
        h.update(s.encode("utf-8"))
        return f"hash_{h.hexdigest()}"

    def _tokenize(self, s: str) -> str:
        if self.cfg.token_secret:
            # deterministic HMAC-based token
            t = hmac.new(self.cfg.token_secret, s.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        else:
            t = uuid.uuid4().hex[:24]
        return f"{self.cfg.token_prefix}{t}"

    def _encrypt(self, s: str, context: Dict[str, str]) -> str:
        if self.cfg.enc_algo != "AES_GCM" or AESGCM is None or not self.cfg.aes_key:
            # fallback to opaque tokenization if AES is not configured
            return self._tokenize(s)
        aesgcm = AESGCM(self.cfg.aes_key)
        nonce = os.urandom(12)
        aad = "|".join([f"{k}:{context.get(k,'')}" for k in self.cfg.aad_fields]).encode("utf-8")
        ct = aesgcm.encrypt(nonce, s.encode("utf-8"), aad)
        blob = base64.b64encode(nonce + ct).decode("utf-8")
        return f"enc:{self.cfg.key_id}:{blob}"

    def _fpe(self, s: str) -> str:
        # Only digits supported in this example (e.g., Aadhaar). Strip non-digits, encrypt, then re-map.
        digits = "".join(ch for ch in s if ch.isdigit())
        if not digits or not self.cfg.fpe_cipher:
            return self._redact(s)
        enc = self.cfg.fpe_cipher.encrypt(digits)
        # format-preserving back into original shape
        out: List[str] = []
        it = iter(enc)
        for ch in s:
            out.append(next(it) if ch.isdigit() else ch)
        return "".join(out)


# -----------------------------
# Orchestrator
# -----------------------------
class MaskingEngine:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.det = Detector(cfg)
        self.tx = Transformer(cfg)

    def mask_text(self, text: str, context: Dict[str, str] = None) -> Dict[str, Any]:
        context = context or {}
        spans = self.det.detect_text(text)
        masked, repl = self.tx.apply_policy_text(text, spans, context)
        return {
            "masked_text": masked,
            "annotations": [span.__dict__ for span in spans]
            # Keep replacement map server-side only in your code paths.
        }

    def mask_json(self, payload: Any, context: Dict[str, str] = None, also_scan_text_nodes: bool = True) -> Dict[str, Any]:
        context = context or {}
        matches = self.det.detect_structured(payload)
        masked_obj, repl1 = self.tx.apply_policy_structured(payload, matches, context)

        # Optional: also run NER/regex inside string nodes
        if also_scan_text_nodes:
            def walk_and_mask(node):
                if isinstance(node, dict):
                    for k, v in node.items():
                        node[k] = walk_and_mask(v)
                elif isinstance(node, list):
                    return [walk_and_mask(x) for x in node]
                elif isinstance(node, str):
                    res = self.mask_text(node, context)
                    return res["masked_text"]
                return node
            masked_obj = walk_and_mask(masked_obj)

        return {
            "masked_json": masked_obj
        }
