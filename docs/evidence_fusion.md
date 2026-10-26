# Observation-aware evidence fusion: implementation and research plan

## Research claim and scope

The proposed contribution is **testing whether graph context, calibrated multivariate
departure, temporal corroboration and observation-sensitivity abstention improve
investigation reliability under imperfect visibility**. The individual algorithms
are established. Combining them is a research hypothesis, not evidence of a new
invention or a priority claim. This implementation is an experimental prototype.

The design targets two failure cases of isolated classifiers: persistent activity
whose marginal features stay below attack thresholds, and suspicious incompletion
that can be explained by missing reverse-path visibility. It retains rule and
RBF-kernel SVM outputs, and stores the new evidence alongside them. It never
changes previous incident records when a counterfactual experiment runs.

## End-to-end changes

Previously the web service constructed features from individual flows and could
substitute `unique_ports=20` based on incompletion. It considered only ten flows
and mainly TCP. That was not the feature representation used during training.
Both live and PCAP web ingestion now use `FeatureExtractor`: measured 5-second
source windows, emitted every second. There is no invented port diversity.
UDP and ICMP windows enter detection too. Live callbacks place parsed metadata
in a bounded 4,096-item queue; inference runs separately and queue drops are counted.

PCAP detection preserves capture event timestamps; playback pacing is separate.
Original capture files are read only. The UI shows source provenance, fallback
reason, warm-up, empirical p-values, temporal evidence, and the visibility test.
Each incident stores the new evidence in SQLite; existing databases migrate by
adding one JSON column. Lineage records include engine and reference identities.

## Mathematical definition

### Non-tree classification and local novelty paths

The supervised path uses a class-balanced RBF-kernel Support Vector Machine.
Its preprocessing is log1p followed by RobustScaler (median and interquartile
range), fitted only on the relevant training fold. For two classes:

    K(z_i,z) = exp(-gamma ||z_i-z||^2)
    f(z) = sum_i alpha_i y_i K(z_i,z) + b

SVC builds pairwise separating boundaries for the four known classes. C=10 and
gamma='scale'. CalibratedClassifierCV uses sigmoid score calibration with
capture-grouped training folds, fitting each fold's preprocessing independently.
The final alert threshold is selected using the separate validation captures.
At least two training captures per class are required. Feature-only synthetic
fixtures use three-fold calibration; they are not labelled capture sessions.
Calibrated class scores are not validated probabilities of real attack intent.

The auxiliary unknown-pattern path uses Local Outlier Factor in novelty mode.
It compares a new window's neighborhood density with its neighbors' densities:

    reachdist_k(p,o) = max(k-distance(o), distance(p,o))
    lrd_k(p) = 1 / mean_o(reachdist_k(p,o))
    LOF_k(p) = mean_o(lrd_k(o) / lrd_k(p))

A larger LOF indicates lower local density than nearby reference samples. The
scikit-learn decision function is negative for outliers and positive for inliers.
The model uses log1p/RobustScaler, up to 20 neighbors, a reference buffer capped at
512 windows, and 10-window warm-up by default. It scores a window before any
admission; anomalous, suspicious or internally degraded windows are quarantined.
A supplementary 4.5-sigma envelope operates on log features. Screening does not
prove benign ground truth or prevent every possible poisoning attack.

The model bundle records `calibrated-rbf-svm-v1`. Unversioned or incompatible
classifier artifacts are rejected with a retraining instruction, so an old model
cannot silently remain active after the algorithm replacement.

### Multivariate, graph, calibration and temporal fusion

For the existing 12-feature vector x, apply y_j=log(1+x_j). Fit data provides
median m_j and MAD scale s_j=max(1.4826 median(|y_j-m_j|),0.05). Then
z_j=(y_j-m_j)/s_j. Ledoit-Wolf fits mean mu and shrinkage covariance

    Sigma = (1-lambda) S + lambda trace(S)/d I + 0.001 I
    D(x) = (z-mu)' inverse(Sigma) (z-mu) / d, d=12

This is robust preprocessing followed by shrinkage covariance; Ledoit-Wolf itself
is not an adversarially robust covariance estimator. The scale floor is a design
choice. The additional diagonal ridge preserves sensitivity when the complete fit
block is constant. Neither is learned from test traffic.

An observed directed edge identifies destination IP, destination service port,
and protocol for a source. The extractor retains at most 256 unique edge tokens
per row and reports truncation. Let E be the current edge set, E0 the frozen
fit-reference edges for that source, and k the current distinct destination count:

    novelty = |E minus E0| / max(|E|,1)
    G(x) = log(1+k) (1+novelty)

For a source absent from fit-reference history, novelty=0: a new source has no
established peer prior. Missing graph context gives G=0. This is an exact bounded
ego-graph statistic, not a GNN, full graph embedding, or MIDAS implementation.

Let w=max(median(D on fit),0.1)/max(median(G on fit),1). The joint nonconformity is

    A(x) = max(D(x), w G(x))

All scoring parameters, including w and edge history, are derived from the fit
block. A disjoint calibration block supplies scores A_1,...,A_n. An empirical
split-conformal upper-tail rank is

    p(x) = (1 + sum_i [A_i >= A(x)]) / (n+1)

The defaults use 32 fit and 64 calibration rows, giving minimum attainable
p=1/65. Separate feature and graph tail ranks are displayed as explanations;
the joint score is calibrated once, so their independence is not assumed.

Each source maintains a one-sided heuristic CUSUM, updated at most every 5 seconds:

    C_t = min(100, max(0, C_(t-1) - log(p_t) - 1.5))

A new-branch anomaly requires p<=0.05 and C>=8, with at least two separated
updates. Evidence resets after a gap greater than 60 seconds. At most 256 source
states are retained with LRU eviction. These numbers are fixed defaults; tune
them using validation sessions before examining a real held-out test set.

Overlapping windows, repeated calibration use, network drift and dependence mean
that these empirical ranks do **not** establish guaranteed real-world false alarm
control. This CUSUM is not an anytime-valid martingale or ADWIN. It does not
silently retrain when suspicious traffic appears.

## Observation-sensitivity intervention

For every scored window, repeat scoring after replacing the log-space response
fraction, completed-handshake fraction, and reset fraction with their fit-reference
medians. The reference and temporal state are not refitted or advanced by this
counterfactual. If the original p<=alpha and masked p>alpha, label it SENSITIVE.

The replacement tests dependence on these observations; it does not reconstruct
missing packets, estimate actual loss, or claim causality. An unknown-pattern
finding dependent on that mask becomes UNCERTAIN. Independent known-rule evidence
remains visible. Known internal drops, late packets, parser errors or state loss
also prevent a SUSPECTED finding from being presented without an uncertainty caveat.

## References, admission and poisoning

The preferred reference uses benign TRAIN sessions for covariance/peer fitting and
benign VALIDATION sessions for calibration. TEST labels never build that reference.
The reference bundle includes rows, configuration and scope; SHA-256 identifies it.
Temporal state never transfers between replay scenarios or source sessions.

Without a supplied reference, the engine can collect rule/model-screened windows
at least 5 seconds apart per source. Internally degraded or legacy-anomalous rows
are excluded. Its label is `automatic-rule-screened-unverified`: unsupervised
screening cannot prove benign traffic, stop all poisoning, or provide independent
ground truth. After 96 admitted rows the reference freezes. Dataset/live switches
discard automatically inferred references. Analyst references require explicit
configuration; synthetic fixture references are refused for live sessions.

The existing short offline demo PCAPs use a separate reference: 16 windows from
synthetic BENIGN TRAIN captures and 32 from BENIGN VALIDATION captures. These
one-second-emitted windows overlap, which is explicitly recorded as
`synthetic-demo-overlapping-reference`. TEST PCAPs are excluded. This makes the
new engine usable during the existing offline demonstration without fabricating
features or claiming independent statistical guarantees. It is discarded on a
transition to LIVE. A custom incomplete demo directory may lack enough reference
windows and will show warm-up instead.

## Source selection

Server startup defaults to `auto`. psutil inspects local adapter status and usable
IP addresses; Scapy must also open a capture backend successfully. No ping, DNS
request, HTTP request or probe is used as a connectivity check. A quiet network
remains LIVE; zero captured packets alone does not trigger a dataset substitution.
Adapter availability does not prove Internet reachability, and a local interface
does not expose every other host's switched or encrypted traffic.

Selection order is usable live interface, then configured PCAP dataset, then
explicitly labeled DEMO/SYNTHETIC fixtures if no dataset exists. Dataset discovery
checks `artifacts/datasets/` then files directly in `artifacts/`; generated demo
captures are not claimed as a real dataset. The supervisor rechecks every 5 seconds,
handles live backend/worker failure or link disconnection, and retries live capture.
Before interrupting a running offline source it verifies that a live backend can
open, so missing drivers do not restart the offline data repeatedly. Dataset EOF
in automatic mode starts a fresh replay session; manual PCAP mode stops at EOF.
Restarting an offline session restarts its statistical state and is visible in status.

Windows live capture requires Npcap and suitable permissions. The current machine
reported no libpcap provider during validation; live success was therefore tested
with capture doubles, while packet processing and offline PCAP ingestion were
exercised with actual Scapy packet objects. Installing a driver remains a machine
setup step, not an algorithm change.

## Reproduce experiments

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m backend.ml.evaluate_fusion
.\.venv\Scripts\python.exe -m backend.ml.evaluate_fusion --manifest artifacts/datasets/manifest.json
```

The first command uses 3 seeded synthetic **feature fixtures**, not real network
captures. They exercise known attacks, new peer/service edges, sustained feature
shift, transient benign bursts, and missing-response ambiguity. They are deliberately
constructed mechanism checks, not independent evidence of superiority. Report and
reference paths are `artifacts/research/fusion_evaluation.json` and
`artifacts/research/fusion_reference.json`. View the report in Model Evaluation.

The manifest runner accepts an array of records:

```json
[
  {"session":"benign-train", "split":"train", "label":"BENIGN", "pcap":"train.pcap"},
  {"session":"benign-validation", "split":"validation", "label":"BENIGN", "pcap":"validation.pcap"},
  {"session":"held-out-attack", "split":"test", "label":"PORT_SCAN", "pcap":"test.pcap", "source":"10.0.0.10"}
]
```

Add labelled attack TRAIN sessions to train a useful SVM comparator. Supply at least
32 nonoverlapping benign train windows, 64 benign validation windows and independent
held-out test captures. Paths are relative to the manifest. IDs, paths and capture
content hashes must be unique. Whole-capture labels presume session-wide behavior;
mixed traffic needs independent per-source labels and onset annotations first.

Comparisons include rules, RBF SVM (C=10, threshold .8), novelty-mode Local Outlier Factor,
the new fusion branch, and fusion with graph, temporal, or visibility components
removed. Fusion ablations evaluate **that branch alone**, not the complete detector
including retained rule/SVM alerts. Metrics include binary precision/recall/F1,
false positive windows, abstentions, 10-second-suppressed false alerts per benign
observation hour, time to first detected attack window, and inference throughput.
An abstention on an attack counts as a miss for recall. Exposure is the union of
benign five-second windows, not number of sources times capture duration.

The current default fixture run (seeds 11, 23, 37; 720 test source windows total)
produced the following aggregate binary results. These are the deliberately
constructed feature fixtures, not a real dataset or the existing demo PCAPs:

| Branch | Precision | Recall | F1 | False positive windows | Abstentions |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rules | 1.000 | 0.600 | 0.750 | 0 | 0 |
| Calibrated RBF-kernel SVM | 0.688 | 0.600 | 0.641 | 90 | 0 |
| Novelty-mode Local Outlier Factor | 0.681 | 0.821 | 0.745 | 127 | 0 |
| Fusion, complete branch | 0.996 | 0.782 | 0.876 | 1 | 86 |
| Fusion, graph removed | 0.996 | 0.727 | 0.841 | 1 | 85 |
| Fusion, temporal removed | 0.976 | 0.867 | 0.918 | 7 | 108 |
| Fusion, visibility removed | 0.757 | 0.791 | 0.773 | 84 | 0 |

Temporal corroboration trades recall and delay for fewer transient false positives;
the complete branch does not maximize F1 in these fixtures. Visibility abstention
also costs some attack recall. Report those costs along with any improvements.
Public dataset superiority and publication novelty remain unverified.

Local integration verification: 109 tests passed, including the trained-model tests,
and the production frontend build passed. Live callback, disconnect and
recovery tests use capture doubles; real offline Scapy ingestion and the existing
synthetic PCAP reference were also exercised. A host smoke check confirmed
DEMO fallback because the Windows packet capture driver is unavailable.

## Evidence needed before a publication claim

Use independently labelled public or institution-approved captures. Split by
capture session and time before extracting windows, reserve unseen attack types,
and report results per dataset and seed. Add calibrated modern baselines and
capture-loss scenarios with the existing Replay Lab. Report uncertainty intervals,
false alerts/hour, attack-onset delay, CPU/memory cost and abstention coverage.
Inspect failures on benign drift, shared NATs, new hosts and asymmetric captures.
Compare the complete production detector as well as the isolated fusion branch.
Ablations must show which component helps and what it costs. A literature review
must establish whether this precise contribution is already published.

## Primary sources

- RBF Support Vector Classification: https://scikit-learn.org/stable/modules/generated/sklearn.svm.SVC.html
- Novelty-mode LOF and its unseen-data restriction: https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html
- Ledoit-Wolf implementation and original-paper attribution: https://scikit-learn.org/stable/modules/generated/sklearn.covariance.LedoitWolf.html
- Conformal anomaly detection and calibration context: https://proceedings.mlr.press/v329/hennhofer26a.html
- CUSUM foundations: https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc323.htm
- Related graph-stream research (inspiration, not implemented MIDAS): https://ojs.aaai.org/index.php/AAAI/article/view/5724
- Related sequential conformal work: https://proceedings.mlr.press/v329/eliades26a.html
