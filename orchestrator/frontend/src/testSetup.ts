// Vitest setup (vite.config.ts `test.setupFiles`). A safety net for slow,
// loaded machines only: tests wait on explicit conditions, and a test that
// needs more than the default wait is fixed, not covered by this limit.
import { configure } from "@testing-library/react";

configure({ asyncUtilTimeout: 5000 });
