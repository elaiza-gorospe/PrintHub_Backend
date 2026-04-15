/**
 * Image generation helper.
 *
 * Production:  fal.ai FLUX.1 [dev]  — requires FAL_KEY + balance
 * Development: Pollinations.AI       — free, no key, set FAL_MOCK=true in .env
 */

const FAL_BASE = "https://fal.run";
const DEFAULT_MODEL = "fal-ai/flux/dev";

const SIZE_MAP = {
  square_hd: [1024, 1024],
  square: [512, 512],
  portrait_4_3: [768, 1024],
  portrait_16_9: [576, 1024],
  landscape_4_3: [1024, 768],
  landscape_16_9: [1024, 576],
};

/**
 * Generate an image from a text prompt.
 * @param {Object} opts
 * @param {string} opts.prompt
 * @param {string} [opts.model]
 * @param {string} [opts.imageSize]
 * @param {number} [opts.numSteps]
 * @returns {Promise<{url: string, width: number, height: number, seed: number|null}>}
 */
async function generateImage({
  prompt,
  model = DEFAULT_MODEL,
  imageSize = "square_hd",
  numSteps = 28,
}) {
  if (process.env.FAL_MOCK === "true") {
    return generateWithPollinations(prompt, imageSize);
  }
  return generateWithFal(prompt, model, imageSize, numSteps);
}

// ── Pollinations.AI (free, no key) ──────────────────────────────────────────
async function generateWithPollinations(prompt, imageSize) {
  const [width, height] = SIZE_MAP[imageSize] || [1024, 1024];
  const seed = Math.floor(Math.random() * 999999);

  const url =
    `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt)}` +
    `?width=${width}&height=${height}&seed=${seed}&nologo=true&model=flux`;

  console.log(`[Pollinations] Generated URL: ${url}`);

  // Return URL directly — Pollinations generates on first browser load, no pre-check needed
  return { url, width, height, seed };
}

// ── fal.ai FLUX.1 ────────────────────────────────────────────────────────────
async function generateWithFal(prompt, model, imageSize, numSteps) {
  const falKey = process.env.FAL_KEY;
  if (!falKey) throw new Error("FAL_KEY environment variable is not set");

  const [width, height] = SIZE_MAP[imageSize] || [1024, 1024];

  const res = await fetch(`${FAL_BASE}/${model}`, {
    method: "POST",
    headers: {
      Authorization: `Key ${falKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      prompt,
      image_size: imageSize,
      num_inference_steps: numSteps,
      guidance_scale: 3.5,
      num_images: 1,
      safety_tolerance: "2",
      output_format: "jpeg",
    }),
  });

  if (!res.ok) {
    let errMsg = `fal.ai error: ${res.status}`;
    try {
      const errBody = await res.json();
      errMsg = errBody?.message || errBody?.detail || errMsg;
    } catch {
      /* ignore */
    }
    throw new Error(errMsg);
  }

  const data = await res.json();
  const image = data?.images?.[0];
  if (!image?.url) throw new Error("fal.ai returned no image URL");

  return {
    url: image.url,
    width: image.width || width,
    height: image.height || height,
    seed: data.seed ?? null,
  };
}

module.exports = { generateImage };
