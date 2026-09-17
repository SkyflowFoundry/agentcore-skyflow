# Sample documents

Synthetic documents used by the demo. Every name and address and phone number
here is invented.

`claim-note.txt` and `claim-note.pdf` and `claim-note.docx` carry the same five
lines so the difference between formats is visible. A `txt` or `docx` comes back
with reversible vault tokens and a `pdf` comes back with one-way counters.

Rebuild the binary formats with `python3 scripts/make_samples.py`. That script
also writes larger files for measuring throughput, and those are gitignored
because they are hundreds of kilobytes of generated filler.

Upload them with:

```bash
aws s3 cp samples/ s3://agentcore-skyflow-files-<account>/samples/ --recursive \
  --exclude "README.md"
```
