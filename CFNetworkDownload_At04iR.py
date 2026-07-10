#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔱 HYDRA SENTINEL-X: MASTER RECONNAISSANCE & ARCHIVIST AGENT
DOMAIN I: NEURO-COGNITIVE ORCHESTRATION & DATA EXTRACTION
VERSION: 9.9.1-OMEGA
AUTHOR: SENTINEL CORP // PRESIDENT & C.E.O. DARYELL MCFARLAND
CLASSIFICATION: OMEGA ROOT // EYES ONLY

This module performs deep semantic extraction, vector archival, and
intelligence surfacing across all HYDRA system artifacts, chat logs,
repositories, and battlefield communications.

USAGE:
    python hail_archivist.py --ingest ./my_repo
    python hail_archivist.py --query "flash loan contract"
    python hail_archivist.py --export --format json
    python hail_archivist.py --sync --watch
"""

import os
import sys
import re
import json
import hashlib
import logging
import fnmatch
import argparse
import time
import threading
import signal
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    import chromadb
    from chromadb.utils import embedding_functions
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# =====================================================================
# CONFIGURATION CONSTANTS
# =====================================================================

DEFAULT_WORKSPACE = "./hail_history_dump"
DEFAULT_DB_DIR = "./omega-memory/chroma_db"
COLLECTION_NAME = "hydra_system_blueprints"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHUNK_SIZE = 512
CHUNK_OVERLAP = 128
MAX_WORKERS = 8

# Sentinel Corporation Crimson/Black/Gold Log Format
LOG_FORMAT = "\033[38;2;139;0;0m[%(asctime)s]\033[0m \033[38;2;212;175;55m[%(levelname)s]\033[0m %(message)s"

# File extensions to target
TARGET_EXTENSIONS = {
    '.py', '.sol', '.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml',
    '.toml', '.md', '.txt', '.sh', '.ps1', '.html', '.css', '.rs', '.go',
    '.java', '.cpp', '.c', '.h', '.rb', '.php', '.swift', '.kt', '.sql',
    '.env', '.conf', '.ini', '.cfg', '.log', '.csv'
}

# =====================================================================
# DATA STRUCTURES
# =====================================================================

@dataclass
class ExtractedPayload:
    """Immutable record of a single extracted intelligence fragment."""
    payload_type: str
    content: str
    source_file: str
    line_number: int
    context: str
    timestamp: str
    checksum: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ArchiveEntry:
    """Vector-storable archive record with full provenance."""
    id: str
    document: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None

@dataclass
class IntelligenceReport:
    """Aggregated intelligence surfacing report."""
    generated_at: str
    query: str
    total_hits: int
    payloads: List[Dict[str, Any]]
    source_files: List[str]
    classification: str = "OMEGA ROOT"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "query": self.query,
            "total_hits": self.total_hits,
            "payloads": self.payloads,
            "source_files": self.source_files,
            "classification": self.classification
        }

# =====================================================================
# LOGGING ORCHESTRATION
# =====================================================================

def _init_logging() -> logging.Logger:
    logger = logging.getLogger("HAIL_ARCHIVIST")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
    return logger

LOG = _init_logging()

# =====================================================================
# PATTERN DEFINITIONS — THE EXTRACTION ARSENAL
# =====================================================================

EXTRACTION_PATTERNS = {
    # ── Cryptographic Assets ──
    "ethereum_address": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "solana_address": re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),
    "private_key": re.compile(r"\b(?:0x)?[a-fA-F0-9]{64}\b"),
    "api_key_generic": re.compile(
        r"\b(?:api[_-]?key|apikey|token|secret)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-]{16,128})["']?",
        re.IGNORECASE
    ),
    "bip39_seed": re.compile(r"\b(?:[a-zA-Z]{3,8}\s+){11,23}[a-zA-Z]{3,8}\b"),
    "contract_address": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),

    # ── Network Infrastructure ──
    "url": re.compile(
        r"https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?"
    ),
    "ip_address": re.compile(
        r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "websocket_endpoint": re.compile(r"wss?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?"),
    "rpc_endpoint": re.compile(r"https?://(?:[a-zA-Z0-9.-]+)\.(?:infura|alchemy|quicknode|ankr)\.[a-z]+/?[a-zA-Z0-9-]*"),
    "discord_webhook": re.compile(r"https?://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+"),
    "telegram_bot_token": re.compile(r"\b\d{9,10}:[a-zA-Z0-9_-]{35}\b"),

    # ── Code Artifacts ──
    "python_code_block": re.compile(r"```python\n(.*?)\n```", re.DOTALL),
    "solidity_code_block": re.compile(r"```solidity\n(.*?)\n```", re.DOTALL),
    "javascript_code_block": re.compile(r"```(?:javascript|js)\n(.*?)\n```", re.DOTALL),
    "typescript_code_block": re.compile(r"```(?:typescript|ts)\n(.*?)\n```", re.DOTALL),
    "bash_code_block": re.compile(r"```(?:bash|sh|shell)\n(.*?)\n```", re.DOTALL),
    "json_code_block": re.compile(r"```json\n(.*?)\n```", re.DOTALL),
    "yaml_code_block": re.compile(r"```(?:yaml|yml)\n(.*?)\n```", re.DOTALL),
    "powershell_code_block": re.compile(r"```(?:powershell|ps1)\n(.*?)\n```", re.DOTALL),
    "rust_code_block": re.compile(r"```rust\n(.*?)\n```", re.DOTALL),
    "generic_code_block": re.compile(r"```\n(.*?)\n```", re.DOTALL),

    # ── Financial & Trading ──
    "dollar_amount": re.compile(r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?"),
    "percentage": re.compile(r"\b\d{1,3}(?:\.\d{1,2})?%\b"),
    "wallet_balance": re.compile(r"(?:balance|bal| holdings)["']?\s*[:=]\s*["']?(\d+\.?\d*)\s*(?:ETH|BTC|USDC|USDT|SOL|STRG|BOOTY)", re.IGNORECASE),
    "profit_split": re.compile(r"(?:split|allocation|distribution)\s*[:=]\s*\d{1,2}%", re.IGNORECASE),

    # ── Identities & Credentials ──
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_number": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ssn_pattern": re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
    "uuid": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),

    # ── HYDRA-Specific Signatures ──
    "hydra_reference": re.compile(r"\b(?:HYDRA|SENTINEL|OMEGA|H\.A\.I\.L\.|MANTICORE|STINKMEANER|CLAWSOULS)\b", re.IGNORECASE),
    "booty_bucks_ref": re.compile(r"(?:BOOTY\s*BUCKS|\$BOOTY|0xedf077e768a1443cdeabc771ecb913c73c2949e8)", re.IGNORECASE),
    "sentinel_corp": re.compile(r"(?:Sentinel\s*Corporation|Daryell\s*McFarland|Slick\s*Dick\s*D)", re.IGNORECASE),
    "tier_reference": re.compile(r"(?:Tier\s*[0-4]|OMEGA\s*ROOT|ExecBoard|Department\s*Admin|Task\s*Swarm)", re.IGNORECASE),
    "clique_reference": re.compile(r"(?:Clique\s*[A-P]|Clawsoul\s*\d+)", re.IGNORECASE),

    # ── Configuration & Secrets ──
    "env_variable": re.compile(r"\b[A-Z_][A-Z0-9_]*\s*=\s*["']?[^"'\s]+["']?"),
    "database_connection": re.compile(r"(?:mongodb|postgres|mysql|redis)://[^"'\s]+", re.IGNORECASE),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "stripe_key": re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
}

# =====================================================================
# INTELLIGENCE ENGINE
# =====================================================================

class IntelligenceEngine:
    """Core extraction and processing engine for all artifact types."""

    def __init__(self, chunk_size: int = CHUNK_SIZE, chunk_overlap: int = CHUNK_OVERLAP):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.payloads: List[ExtractedPayload] = []
        self._lock = threading.Lock()

    def compute_checksum(self, content: str) -> str:
        """Generate SHA-256 checksum for deduplication."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def semantic_chunk(self, text: str, source_file: str) -> List[Dict[str, Any]]:
        """Split text into overlapping semantic chunks for vector storage."""
        chunks = []
        start = 0
        text_len = len(text)

        while start < text_len:
            end = min(start + self.chunk_size, text_len)
            # Try to break at newline or space
            if end < text_len:
                last_newline = text.rfind('\n', start, end)
                last_space = text.rfind(' ', start, end)
                break_point = last_newline if last_newline != -1 else last_space
                if break_point != -1 and break_point > start + self.chunk_size // 2:
                    end = break_point

            chunk_text = text[start:end].strip()
            if chunk_text:
                chunks.append({
                    "text": chunk_text,
                    "start": start,
                    "end": end,
                    "source": source_file
                })
            start = end - self.chunk_overlap if end < text_len else end

        return chunks

    def extract_patterns(self, content: str, source_file: str) -> List[ExtractedPayload]:
        """Run full pattern arsenal against content."""
        payloads = []
        timestamp = datetime.utcnow().isoformat() + "Z"

        for pattern_name, pattern in EXTRACTION_PATTERNS.items():
            for match in pattern.finditer(content):
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                # Extract context (100 chars before/after)
                ctx_start = max(0, match.start() - 100)
                ctx_end = min(len(content), match.end() + 100)
                context = content[ctx_start:ctx_end].replace('\n', ' ')

                payload = ExtractedPayload(
                    payload_type=pattern_name,
                    content=match.group(0),
                    source_file=source_file,
                    line_number=line_num,
                    context=context,
                    timestamp=timestamp,
                    checksum=self.compute_checksum(match.group(0)),
                    metadata={
                        "match_start": match.start(),
                        "match_end": match.end(),
                        "pattern": pattern_name
                    }
                )
                payloads.append(payload)

        return payloads

    def process_file(self, file_path: Path) -> Tuple[List[ExtractedPayload], List[Dict[str, Any]]]:
        """Process a single file: extract patterns and chunk for vectors."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            LOG.error(f"\033[38;2;139;0;0mFailed to read {file_path}: {e}\033[0m")
            return [], []

        source_str = str(file_path)
        payloads = self.extract_patterns(content, source_str)
        chunks = self.semantic_chunk(content, source_str)

        # Add file-level metadata to payloads
        for p in payloads:
            p.metadata["file_size"] = len(content)
            p.metadata["file_extension"] = file_path.suffix

        return payloads, chunks

    def ingest_directory(self, root_path: Path, max_workers: int = MAX_WORKERS) -> Dict[str, Any]:
        """Crawl directory and extract intelligence from all target files."""
        target_files = []
        for ext in TARGET_EXTENSIONS:
            target_files.extend(root_path.rglob(f"*{ext}"))

        # Exclude common junk
        excluded_patterns = ['node_modules', '.git', '__pycache__', '.venv', 'venv', 
                           'dist', 'build', '.pytest_cache', '.mypy_cache', 'target']
        target_files = [f for f in target_files if not any(p in str(f) for p in excluded_patterns)]

        LOG.info(f"\033[38;2;212;175;55m[RECONNAISSANCE]\033[0m Scanning {len(target_files)} files in {root_path}")

        all_payloads = []
        all_chunks = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(self.process_file, f): f for f in target_files}
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    payloads, chunks = future.result()
                    all_payloads.extend(payloads)
                    all_chunks.extend(chunks)
                    if payloads:
                        LOG.debug(f"\033[38;2;139;0;0m[EXTRACT]\033[0m {len(payloads)} payloads from {file_path.name}")
                except Exception as e:
                    LOG.error(f"\033[38;2;139;0;0m[ERROR]\033[0m Processing {file_path}: {e}")

        # Deduplicate by checksum
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p.checksum not in seen:
                seen.add(p.checksum)
                unique_payloads.append(p)

        with self._lock:
            self.payloads.extend(unique_payloads)

        stats = defaultdict(int)
        for p in unique_payloads:
            stats[p.payload_type] += 1

        LOG.info(f"\033[38;2;212;175;55m[INTEL SUMMARY]\033[0m Extracted {len(unique_payloads)} unique payloads across {len(stats)} categories")

        return {
            "total_files": len(target_files),
            "total_payloads": len(unique_payloads),
            "total_chunks": len(all_chunks),
            "category_breakdown": dict(stats),
            "payloads": [p.to_dict() for p in unique_payloads],
            "chunks": all_chunks
        }

# =====================================================================
# VECTOR MEMORY CORE (CHROMADB)
# =====================================================================

class VectorMemoryCore:
    """Persistent vector storage and semantic retrieval using ChromaDB."""

    def __init__(self, db_dir: str = DEFAULT_DB_DIR, collection_name: str = COLLECTION_NAME):
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.collection_name = collection_name
        self.client = None
        self.collection = None
        self.embedding_func = None

        if not CHROMADB_AVAILABLE:
            LOG.warning("\033[38;2;212;175;55m[WARNING]\033[0m ChromaDB not installed. Vector operations disabled.")
            return

        self._init_db()

    def _init_db(self):
        """Initialize ChromaDB persistent client."""
        try:
            self.client = chromadb.PersistentClient(path=str(self.db_dir))
            self.embedding_func = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=EMBEDDING_MODEL
            )
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_func,
                metadata={"hail_version": "9.9.1-OMEGA", "classification": "OMEGA ROOT"}
            )
            LOG.info(f"\033[38;2;212;175;55m[VECTOR CORE]\033[0m ChromaDB initialized at {self.db_dir}")
        except Exception as e:
            LOG.error(f"\033[38;2;139;0;0m[VECTOR ERROR]\033[0m Failed to init ChromaDB: {e}")
            self.client = None

    def archive_chunks(self, chunks: List[Dict[str, Any]], source_tag: str = "ingest"):
        """Store semantic chunks in vector database."""
        if not self.collection or not chunks:
            return 0

        ids = []
        documents = []
        metadatas = []

        for i, chunk in enumerate(chunks):
            chunk_id = f"{source_tag}_{self._hash(chunk['text'])}_{i}"
            ids.append(chunk_id)
            documents.append(chunk["text"])
            metadatas.append({
                "source_file": chunk.get("source", "unknown"),
                "start": chunk.get("start", 0),
                "end": chunk.get("end", 0),
                "ingested_at": datetime.utcnow().isoformat(),
                "tag": source_tag
            })

        try:
            self.collection.add(ids=ids, documents=documents, metadatas=metadatas)
            LOG.info(f"\033[38;2;212;175;55m[ARCHIVE]\033[0m Stored {len(ids)} vectors")
            return len(ids)
        except Exception as e:
            LOG.error(f"\033[38;2;139;0;0m[ARCHIVE ERROR]\033[0m {e}")
            return 0

    def query(self, query_text: str, n_results: int = 10, 
              filter_tags: Optional[List[str]] = None) -> IntelligenceReport:
        """Semantic search across archived intelligence."""
        if not self.collection:
            return IntelligenceReport(
                generated_at=datetime.utcnow().isoformat(),
                query=query_text,
                total_hits=0,
                payloads=[],
                source_files=[]
            )

        where_filter = None
        if filter_tags:
            where_filter = {"tag": {"$in": filter_tags}}

        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=n_results,
                where=where_filter
            )

            payloads = []
            source_files = set()

            for i, doc in enumerate(results.get('documents', [[]])[0]):
                metadata = results.get('metadatas', [[]])[0][i] if results.get('metadatas') else {}
                distance = results.get('distances', [[]])[0][i] if results.get('distances') else 0

                payloads.append({
                    "document": doc,
                    "metadata": metadata,
                    "relevance_score": 1.0 - min(distance, 1.0),
                    "rank": i + 1
                })
                if metadata and "source_file" in metadata:
                    source_files.add(metadata["source_file"])

            report = IntelligenceReport(
                generated_at=datetime.utcnow().isoformat(),
                query=query_text,
                total_hits=len(payloads),
                payloads=payloads,
                source_files=list(source_files)
            )

            LOG.info(f"\033[38;2;212;175;55m[QUERY]\033[0m '{query_text}' → {len(payloads)} hits")
            return report

        except Exception as e:
            LOG.error(f"\033[38;2;139;0;0m[QUERY ERROR]\033[0m {e}")
            return IntelligenceReport(
                generated_at=datetime.utcnow().isoformat(),
                query=query_text,
                total_hits=0,
                payloads=[],
                source_files=[]
            )

    def get_stats(self) -> Dict[str, Any]:
        """Return database statistics."""
        if not self.collection:
            return {"status": "offline", "count": 0}
        try:
            count = self.collection.count()
            return {
                "status": "online",
                "collection": self.collection_name,
                "vectors": count,
                "db_path": str(self.db_dir),
                "embedding_model": EMBEDDING_MODEL
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()[:8]

# =====================================================================
# FILE SYSTEM WATCHER
# =====================================================================

class HailEventHandler(FileSystemEventHandler):
    """Watchdog handler for real-time ingestion."""

    def __init__(self, engine: IntelligenceEngine, memory: VectorMemoryCore):
        self.engine = engine
        self.memory = memory
        self.pending_files: Set[str] = set()
        self._timer = None
        self.batch_lock = threading.Lock()

    def on_modified(self, event):
        if event.is_directory:
            return
        if Path(event.src_path).suffix in TARGET_EXTENSIONS:
            with self.batch_lock:
                self.pending_files.add(event.src_path)
            self._debounced_process()

    def on_created(self, event):
        if event.is_directory:
            return
        if Path(event.src_path).suffix in TARGET_EXTENSIONS:
            with self.batch_lock:
                self.pending_files.add(event.src_path)
            self._debounced_process()

    def _debounced_process(self, delay: float = 2.0):
        """Batch process files to avoid thrashing."""
        if self._timer:
            self._timer.cancel()
        self._timer = threading.Timer(delay, self._flush_batch)
        self._timer.start()

    def _flush_batch(self):
        with self.batch_lock:
            files = list(self.pending_files)
            self.pending_files.clear()

        for f in files:
            LOG.info(f"\033[38;2;139;0;0m[WATCH]\033[0m Ingesting {f}")
            payloads, chunks = self.engine.process_file(Path(f))
            if chunks:
                self.memory.archive_chunks(chunks, source_tag="watch")

# =====================================================================
# EXPORT & REPORTING
# =====================================================================

class ReportExporter:
    """Generate formatted intelligence reports."""

    @staticmethod
    def export_json(data: Dict[str, Any], output_path: Path):
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        LOG.info(f"\033[38;2;212;175;55m[EXPORT]\033[0m JSON → {output_path}")

    @staticmethod
    def export_markdown(report: IntelligenceReport, output_path: Path):
        lines = [
            "# 🔱 HYDRA SENTINEL-X INTELLIGENCE REPORT",
            f"**Classification:** {report.classification}",
            f"**Generated:** {report.generated_at}",
            f"**Query:** `{report.query}`",
            f"**Total Hits:** {report.total_hits}",
            "",
            "## Source Files",
        ]
        for sf in report.source_files:
            lines.append(f"- `{sf}`")
        lines.extend(["", "## Payloads"])

        for i, payload in enumerate(report.payloads, 1):
            lines.extend([
                f"### Hit #{i}",
                f"- **Relevance:** {payload.get('relevance_score', 0):.3f}",
                f"- **Source:** `{payload.get('metadata', {}).get('source_file', 'unknown')}`",
                "",
                "```",
                payload.get('document', '')[:500],
                "```",
                "---"
            ])

        output_path.write_text('\n'.join(lines), encoding='utf-8')
        LOG.info(f"\033[38;2;212;175;55m[EXPORT]\033[0m Markdown → {output_path}")

    @staticmethod
    def export_payloads_csv(payloads: List[Dict[str, Any]], output_path: Path):
        import csv
        if not payloads:
            return
        keys = list(payloads[0].keys())
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(payloads)
        LOG.info(f"\033[38;2;212;175;55m[EXPORT]\033[0m CSV → {output_path}")

# =====================================================================
# CLI & MAIN ORCHESTRATION
# =====================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="🔱 HYDRA SENTINEL-X Master Reconnaissance & Archivist Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --ingest ./my_repo --db ./omega-memory
  %(prog)s --query "flash loan vulnerability" --n 20
  %(prog)s --export --format json --output ./intel_dump.json
  %(prog)s --sync --watch ./src
        """
    )

    parser.add_argument('--ingest', metavar='PATH', help='Ingest directory into vector memory')
    parser.add_argument('--query', metavar='TEXT', help='Semantic query against archive')
    parser.add_argument('--n', type=int, default=10, help='Number of query results (default: 10)')
    parser.add_argument('--export', action='store_true', help='Export current payloads')
    parser.add_argument('--format', choices=['json', 'markdown', 'csv'], default='json', help='Export format')
    parser.add_argument('--output', metavar='PATH', default='./hail_export', help='Output path')
    parser.add_argument('--db', metavar='PATH', default=DEFAULT_DB_DIR, help='ChromaDB directory')
    parser.add_argument('--sync', action='store_true', help='Sync mode (batch + watch)')
    parser.add_argument('--watch', metavar='PATH', help='Watch directory for changes')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    parser.add_argument('--workers', type=int, default=MAX_WORKERS, help='Thread pool size')

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Sentinel banner
    print("\033[38;2;139;0;0m")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  🔱  HYDRA SENTINEL-X  //  MASTER ARCHIVIST  v9.9.1-OMEGA   ║")
    print("║     SENTINEL CORPORATION  //  PRESIDENT & C.E.O.             ║")
    print("║     DARYELL MCFARLAND  //  OMEGA ROOT CLEARANCE            ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("\033[0m")

    engine = IntelligenceEngine()
    memory = VectorMemoryCore(db_dir=args.db)

    # Stats mode
    if args.stats:
        stats = memory.get_stats()
        print(json.dumps(stats, indent=2))
        return

    # Ingest mode
    if args.ingest:
        ingest_path = Path(args.ingest)
        if not ingest_path.exists():
            LOG.error(f"\033[38;2;139;0;0m[FATAL]\033[0m Path not found: {ingest_path}")
            sys.exit(1)

        result = engine.ingest_directory(ingest_path, max_workers=args.workers)
        if memory.client:
            memory.archive_chunks(result.get("chunks", []), source_tag="ingest")

        # Auto-export if requested
        if args.export:
            out = Path(args.output)
            out.mkdir(parents=True, exist_ok=True)
            ReportExporter.export_json(result, out / "ingest_report.json")
            if result.get("payloads"):
                ReportExporter.export_payloads_csv(
                    result["payloads"], out / "payloads.csv"
                )

    # Query mode
    if args.query:
        report = memory.query(args.query, n_results=args.n)
        print(json.dumps(report.to_dict(), indent=2, default=str))
        if args.export:
            out = Path(args.output)
            out.mkdir(parents=True, exist_ok=True)
            ReportExporter.export_markdown(report, out / f"query_{int(time.time())}.md")

    # Watch mode
    if args.watch and WATCHDOG_AVAILABLE:
        watch_path = Path(args.watch)
        if not watch_path.exists():
            LOG.error(f"\033[38;2;139;0;0m[FATAL]\033[0m Watch path not found: {watch_path}")
            sys.exit(1)

        event_handler = HailEventHandler(engine, memory)
        observer = Observer()
        observer.schedule(event_handler, str(watch_path), recursive=True)
        observer.start()

        LOG.info(f"\033[38;2;212;175;55m[WATCH]\033[0m Monitoring {watch_path} for changes...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    elif args.watch and not WATCHDOG_AVAILABLE:
        LOG.error("\033[38;2;139;0;0m[FATAL]\033[0m Install watchdog: pip install watchdog")
        sys.exit(1)

    # If no action specified
    if not any([args.ingest, args.query, args.watch, args.stats]):
        parser.print_help()

if __name__ == "__main__":
    main()
