# Microsoft Threat Actor Naming support

This update adds Microsoft public threat actor naming data from the MicrosoftMapping.json feed referenced by Microsoft Learn.

The normalizer only adds Microsoft names when the Microsoft record can be matched to exactly one existing MITRE/MISP actor through an exact normalized name match. Ambiguous or unmatched Microsoft records are written to:

```text
data/normalized/review-candidates.json
```

This avoids creating unsafe `same-as` mappings automatically.
