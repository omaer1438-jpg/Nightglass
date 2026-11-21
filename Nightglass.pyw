"""Desktop launcher: runs the app from source with the installed app's cases (Defender blocks the unsigned exe)."""

import os
import sys

os.environ.setdefault("NIGHTGLASS_DATA_DIR", os.path.join(os.environ["LOCALAPPDATA"], "Programs", "Nightglass", "cases"))

from app.__main__ import main  # noqa: E402

sys.exit(main())
