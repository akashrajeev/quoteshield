"""Real public documents used as benign host text. Provenance integrity plus what the firewall actually does on them.
The false-positive pin is an observation about dev fixtures, not a rate."""
import hashlib, json, unittest
from pathlib import Path
import shield

ROOT = Path(__file__).resolve().parent.parent
IDX = json.loads((ROOT / 'corpus/real/PROVENANCE.json').read_text())['documents']

class Provenance(unittest.TestCase):
    def test_every_document_has_complete_provenance_and_matching_hash(self):
        for d in IDX:
            for k in ('source_id', 'domain', 'origin_url', 'retrieved_at', 'sha256', 'license_note', 'path'):
                self.assertTrue(d.get(k), (d.get('source_id'), k))
            self.assertTrue(d['origin_url'].startswith('https://'))
            data = (ROOT / d['path']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), d['sha256'], d['source_id'])
            self.assertEqual(len(data), d['bytes']); self.assertLess(len(data), 32768)

    def test_covers_five_domains_once_each(self):
        self.assertEqual(sorted(d['domain'] for d in IDX), ['customer_support', 'finance', 'hr', 'procurement', 'research'])

    def test_no_document_carries_injected_content(self):
        for d in IDX:
            t = (ROOT / d['path']).read_text().lower()
            self.assertNotIn('canary', t); self.assertNotIn('ignore previous', t)

class FirewallOnRealText(unittest.TestCase):
    def rules(self, d):
        return [f['rule'] for f in shield.firewall((ROOT / d['path']).read_text())['findings']]

    def test_four_documents_pass_clean(self):
        for d in IDX:
            if d['domain'] != 'research': self.assertEqual(self.rules(d), [], d['source_id'])

    def test_known_false_positive_on_contact_lines(self):
        # Observed: "Email: name@agency.gov" contact lines match the unauthorized-disclosure rule. A benign real
        # page is flagged. Pinned so the behaviour is visible; changing the rule is a separate, reviewed change.
        d = [x for x in IDX if x['domain'] == 'research'][0]
        self.assertEqual(self.rules(d), ['unauthorized disclosure instruction'])
        f = shield.firewall((ROOT / d['path']).read_text())['findings'][0]
        self.assertIn('@nih.gov', f['snippet'])

if __name__ == '__main__': unittest.main()
