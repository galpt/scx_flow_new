# nn_hint

Offline hint experiment with no scheduler change.

The model replays raw frame or harness rows offline with
integer adds plus multiplies plus rectified units only.
It keeps two inputs plus two hidden units plus one output
in a few integers that fit in cache with no float use.
The output clamps to the share range with saturation.
There is no BPF inference: BPF has no float plus a small
stack plus bounded loops with divide only in fair charging,
so inference stays in userspace. The hint never writes vd (virtual deadline)
and never steers placement. It makes no faster claim over
averaging and ships as a removable probe: delete this dir
with no scheduler edit. Pointman raw frames plus Lestat frametime feed burst
replay only with no queue inference. Burst maps to zero for lat plus one for batch plus two for idle with shares 400 plus 100 plus 20 report only and calibration still required.
