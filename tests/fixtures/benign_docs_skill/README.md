# Usage

Install dependencies:

```bash
pip install rich
```

Call the API (example):

```bash
curl https://api.example.com/v1/format -d '{"text": "hi"}'
```

Configuration uses the `.env` format. The viewer styles a `.toast.visible {}`
element. Results are dispatched per type:

```python
if result.type == "succeeded":
    print("done")
```
