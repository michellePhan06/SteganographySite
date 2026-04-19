# StegoVault — Flask Steganography Web Application

## Project Structure

```
stegapp/
├── app.py              # Flask application, routes, auth, DB models
├── steganography.py    # Core steg engine (embed / extract)
├── filters.py          # Jinja2 template filters (reference)
├── requirements.txt
├── templates/
│   ├── base.html       # Layout, nav, flash messages
│   ├── index.html      # Public gallery
│   ├── login.html
│   ├── register.html
│   ├── submit.html     # Authenticated upload + steg parameters
│   └── post.html       # Public post view + authenticated extraction
├── posts/              # Output steg-encoded files (served publicly)
└── uploads/            # Temporary uploads (not served publicly)
```

## Installation & Local Run

```bash
pip install -r requirements.txt
python3 main.py
# → http://127.0.0.1:8000
```

## Steganography Algorithm

### Parameters
| Symbol | Name       | Meaning                                             |
|--------|------------|-----------------------------------------------------|
| P      | Carrier    | The public "plaintext" carrier file (any format)    |
| M      | Message    | The secret payload (any format)                     |
| S      | Start bit  | Bits to skip at the head of P (protects headers)    |
| L      | Period     | Embed every L-th bit; cycling mode uses a list      |
| C      | Mode       | `fixed` (one L) or `cycling` (list of L values)     |

### Embedding (fixed mode)
The i-th payload bit replaces carrier bit at:

```
pos(i) = S + (i + 1) * L
```

### Embedding (cycling mode)
```
pos(i) = S + Σ L[k mod len(periods)]   for k in 0..i
```

### Extraction
Deterministic given S, L, mode, and message_len_bits — read the bits from the
same positions that were written during embedding.

### Reversibility
Since only the LSB at computed positions is overwritten, the carrier remains
visually/audibly indistinguishable (for typical values of L ≥ 8).  The
original carrier is NOT recoverable (bits are overwritten), but M is fully
recoverable from the stego-file given correct parameters.

---

## Security Analysis: Finding M given only L

An attacker who knows **only L** faces the following challenge:

1. **Phase ambiguity**: Without S, they don't know where to start. They must
   try all S ∈ [0, L-1] (or up to len(P) bits in the worst case).

2. **Statistical attack on S**:
   - Extract the candidate bitstream for each candidate S.
   - Measure byte-level entropy, chi-square fit to uniform distribution, and
     bigram frequencies.
   - The correct S will yield a bitstream whose byte statistics match the
     expected distribution of M's file type (e.g., ASCII text has low entropy;
     JPEGs have a known header).

3. **Cycling mode multiplies the key space**:
   - Attacker must also guess the cycling sequence (ordered list of L values).
   - Even knowing all L values individually, permutations number |L|!.
   - Brute-force complexity: O(len(P) × |L|! × candidate_M_types).

4. **Practical defense recommendations**:
   - Use a large S (e.g., S = 1024 for typical image headers).
   - Use cycling mode with a long, non-repeating sequence.
   - Encrypt M before embedding (the steganography only *hides* M; it does
     not encrypt it).

5. **What the attacker CAN determine**:
   - Approximate length of M (from file size and L: roughly len(P) / L bytes).
   - File type hints if M is unencrypted and the attacker correctly guesses S.

---

## Deployment (UTA Azure / AWS Free Tier)

### Azure App Service (free tier)
```bash
# Install Azure CLI, then:
az login
az group create --name StegoVault --location eastus
az appservice plan create --name stego-plan --resource-group StegoVault \
    --sku F1 --is-linux
az webapp create --name stego-vault --resource-group StegoVault \
    --plan stego-plan --runtime "PYTHON:3.11"
az webapp up --name stego-vault --resource-group StegoVault
```

Add a `startup.txt` or Procfile:
```
web: gunicorn app:app
```

### AWS Elastic Beanstalk (free tier)
```bash
pip install awsebcli
eb init stegapp --platform python-3.11
eb create stegapp-env
eb deploy
```

### Important for production
- Replace `SECRET_KEY = os.urandom(32)` with a fixed env var.
- Use PostgreSQL instead of SQLite (Azure Database for PostgreSQL / AWS RDS).
- Use Azure Blob Storage / AWS S3 for `posts/` folder (persistent storage).
- Add HTTPS (Azure provides it automatically; AWS needs ACM certificate).
- Set `MAX_CONTENT_LENGTH` appropriately for your hosting tier.

### Credit
 - Ai was used in making the README.md