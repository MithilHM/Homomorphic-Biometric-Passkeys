/**
 * Web client entry point.
 *
 * Deliberately thin: everything the app does lives in `App`, `FlowController`
 * and `CameraController`, all of which are plain TypeScript with no
 * third-party runtime dependency.
 */

import { App } from "./app.js";
import { CameraController } from "./camera.js";

const root = document.getElementById("app");
if (!root) {
  throw new Error("#app container is missing from the document");
}

// Best-effort camera permission for the session, so the first capture prompt
// is not a surprise. Denied permission is an expected state, not an error.
if (CameraController.isSupported() && localStorage.getItem("homobio.cameraHinted") !== "true") {
  localStorage.setItem("homobio.cameraHinted", "true");
}

const app = App.create(root);
(globalThis as unknown as { homobio: App }).homobio = app;
