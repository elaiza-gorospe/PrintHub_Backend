/**
 * 3D Model generation helper using Meshy API.
 *
 * Supports:
 *   - Text-to-3D: Generate 3D model from text prompt
 *   - Image-to-3D: Generate 3D model from reference image + optional description
 *
 * Meshy API is async — tasks are submitted and polled until completion.
 */

const MESHY_BASE = "https://api.meshyai.com/v2";
const MESHY_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes max wait
const MESHY_POLL_INTERVAL_MS = 3000; // Poll every 3 seconds

/**
 * Check if Meshy is properly configured
 */
function validateMeshyConfig() {
  const key = process.env.MESHY_API_KEY;
  if (!key) {
    throw new Error("MESHY_API_KEY environment variable is not set");
  }
  return key;
}

/**
 * Generate a 3D model from a text prompt using Meshy text-to-3D API
 * @param {Object} opts
 * @param {string} opts.prompt - Description of the 3D model to generate
 * @param {string} [opts.quality] - "draft", "standard", or "preview" (default: "standard")
 * @returns {Promise<{glbUrl: string, meshyTaskId: string}>}
 */
async function generateModelFromText({ prompt, quality = "standard" }) {
  const apiKey = validateMeshyConfig();

  console.log(
    `[Meshy] Submitting text-to-3D task: "${prompt.slice(0, 60)}..."`,
  );

  // 1. Submit text-to-3D task
  const submitRes = await fetch(`${MESHY_BASE}/text-to-3d`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      prompt: prompt.trim(),
      quality,
      model_type: "default",
    }),
  });

  if (!submitRes.ok) {
    let errMsg = `Meshy text-to-3D submission error: ${submitRes.status}`;
    try {
      const errBody = await submitRes.json();
      errMsg = errBody?.message || errBody?.error || errMsg;
    } catch {
      /* ignore */
    }
    throw new Error(errMsg);
  }

  const taskData = await submitRes.json();
  const taskId = taskData.result?.id;
  if (!taskId) throw new Error("Meshy did not return a task ID");

  console.log(`[Meshy] Task submitted: ${taskId}`);

  // 2. Poll for task completion
  const result = await pollMeshyTask(apiKey, taskId);
  return result;
}

/**
 * Generate a 3D model from an image using Meshy image-to-3D API
 * @param {Object} opts
 * @param {string} opts.imageUrl - URL of the reference image
 * @param {string} [opts.description] - Optional text description to enhance generation
 * @param {string} [opts.quality] - "draft", "standard", or "preview" (default: "standard")
 * @returns {Promise<{glbUrl: string, meshyTaskId: string}>}
 */
async function generateModelFromImage({
  imageUrl,
  description,
  quality = "standard",
}) {
  const apiKey = validateMeshyConfig();

  console.log(
    `[Meshy] Submitting image-to-3D task: ${imageUrl}${description ? ` with description: "${description.slice(0, 60)}..."` : ""}`,
  );

  // 1. Submit image-to-3D task
  const submitRes = await fetch(`${MESHY_BASE}/image-to-3d`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      image_url: imageUrl,
      description: description ? description.trim() : undefined,
      quality,
      model_type: "default",
    }),
  });

  if (!submitRes.ok) {
    let errMsg = `Meshy image-to-3D submission error: ${submitRes.status}`;
    try {
      const errBody = await submitRes.json();
      errMsg = errBody?.message || errBody?.error || errMsg;
    } catch {
      /* ignore */
    }
    throw new Error(errMsg);
  }

  const taskData = await submitRes.json();
  const taskId = taskData.result?.id;
  if (!taskId) throw new Error("Meshy did not return a task ID");

  console.log(`[Meshy] Task submitted: ${taskId}`);

  // 2. Poll for task completion
  const result = await pollMeshyTask(apiKey, taskId);
  return result;
}

/**
 * Poll Meshy task status until completion
 * @private
 * @param {string} apiKey - Meshy API key
 * @param {string} taskId - Meshy task ID
 * @returns {Promise<{glbUrl: string, meshyTaskId: string}>}
 */
async function pollMeshyTask(apiKey, taskId) {
  const startTime = Date.now();

  while (Date.now() - startTime < MESHY_TIMEOUT_MS) {
    const statusRes = await fetch(`${MESHY_BASE}/text-to-3d/${taskId}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${apiKey}`,
      },
    });

    if (!statusRes.ok) {
      let errMsg = `Meshy status check error: ${statusRes.status}`;
      try {
        const errBody = await statusRes.json();
        errMsg = errBody?.message || errBody?.error || errMsg;
      } catch {
        /* ignore */
      }
      throw new Error(errMsg);
    }

    const statusData = await statusRes.json();
    const task = statusData.result;

    console.log(
      `[Meshy] Task ${taskId} status: ${task.status} (elapsed: ${Math.round((Date.now() - startTime) / 1000)}s)`,
    );

    if (task.status === "COMPLETED") {
      const glbUrl = task.model_urls?.glb;
      if (!glbUrl) {
        throw new Error("Meshy task completed but no GLB URL returned");
      }
      console.log(`✅ [Meshy] Task ${taskId} completed: ${glbUrl}`);
      return { glbUrl, meshyTaskId: taskId };
    }

    if (task.status === "FAILED") {
      throw new Error(
        `Meshy task failed: ${task.error_message || "Unknown error"}`,
      );
    }

    if (task.status === "EXPIRED") {
      throw new Error("Meshy task expired");
    }

    // Still processing, wait before polling again
    await new Promise((resolve) => setTimeout(resolve, MESHY_POLL_INTERVAL_MS));
  }

  throw new Error(
    `Meshy task ${taskId} did not complete within ${Math.round(MESHY_TIMEOUT_MS / 1000)} seconds`,
  );
}

module.exports = {
  generateModelFromText,
  generateModelFromImage,
};
