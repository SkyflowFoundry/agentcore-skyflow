# Sample documents

Synthetic documents used by the demo. Every name and address and phone number
here is invented.

`dispute-case-note.txt` and `dispute-case-note.docx` and `dispute-case-note.pdf`
carry the same card-dispute note, the one the blog post shows, so the
difference between formats is visible. The card number is the standard Visa
test number and the phone number is in the range reserved for fiction. A `txt`
or `docx` comes back with reversible vault tokens and a `pdf` comes back with
one-way counters.

Rebuild all three with `python3 scripts/make_samples.py`.

Upload them with the script that creates the document bucket, which is safe to
re-run once the bucket exists:

```bash
uv run --with boto3 python scripts/create_documents_bucket.py \
  --region us-east-1 --upload-samples
```
