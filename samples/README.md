# Sample documents

Synthetic documents used by the demo. Every name and address and phone number
here is invented.

`claim-note.txt` and `claim-note.pdf` and `claim-note.docx` carry the same five
lines so the difference between formats is visible. A `txt` or `docx` comes back
with reversible vault tokens and a `pdf` comes back with one-way counters.

Rebuild the binary formats with `python3 scripts/make_samples.py`.

Upload them with the script that creates the document bucket, which is safe to
re-run once the bucket exists:

```bash
uv run --with boto3 python scripts/create_documents_bucket.py \
  --region us-east-1 --upload-samples
```
