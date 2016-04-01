Config:

~/.pbp
```bash
.pbp
├── config
├── keyrings
│   └── friends.json
└── keys
    ├── alice.pem.pub
    ├── bob.pem.pub
    └── carol.pem.pub
```

2 directories, 4 files

```json
{
  "me": {
    "pubkey": "<sha2 hash>",
    "privkey": "<sha2 hash>"
  },
  "keys": {
    "alice": {
      "id": "<sha2 hash>",
      "trusted": 1
    },
    "bob": {
      "id": "<sha2 hash>",
      "trusted": 1
    },
    "carol": {
      "id": "<sha2 hash>",
      "trusted": 1
    },
    "derek": {
      "id": "<sha2 hash>",
      "trusted": 1
    }
  },
  "keyrings": {
    "friends": {
      "complete": 1
    }
  }
}
```
