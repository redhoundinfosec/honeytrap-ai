"""OpenSearch sink -- a thin compatibility wrapper around the ES sink.

The bulk API is wire-compatible between OpenSearch 1.x/2.x and
Elasticsearch 7.x/8.x for our purposes (POST /_bulk + NDJSON), so we
inherit unchanged. The class exists separately so users can pick it
explicitly in ``profile.yaml`` and so the metric labels reflect the
correct backend.
"""

from __future__ import annotations

from honeytrap.sinks.elasticsearch import ElasticsearchConfig, ElasticsearchSink


class OpenSearchSink(ElasticsearchSink):
    """OpenSearch flavour of the bulk-API sink."""

    def __init__(self, config: ElasticsearchConfig, *, name: str = "opensearch") -> None:
        """Construct the sink with the OpenSearch metric label."""
        super().__init__(config, name=name)
