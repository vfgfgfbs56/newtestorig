#include <stdint.h>

static uint32_t clamp_u32(uint32_t value, uint32_t min_value, uint32_t max_value) {
  if (value < min_value) return min_value;
  if (value > max_value) return max_value;
  return value;
}

__attribute__((visibility("default"))) uint32_t jend_core_version(void) {
  return 0x00090001u;
}

__attribute__((visibility("default"))) uint32_t jend_guard_min_delay(
  uint32_t action,
  uint32_t pressure,
  uint32_t known_device
) {
  uint32_t delay = action == 1u ? 950u : 650u; /* register : qr-create */
  if (!known_device) delay += 250u;
  if (pressure > 8u) delay += (pressure - 8u) * 90u;
  return clamp_u32(delay, 500u, 4000u);
}

__attribute__((visibility("default"))) int32_t jend_guard_score(
  uint32_t action,
  uint32_t age_ms,
  uint32_t pressure,
  uint32_t known_device,
  uint32_t header_flags,
  uint32_t previous_failures
) {
  int32_t score = 100;
  const uint32_t minimum = jend_guard_min_delay(action, pressure, known_device);

  if (age_ms < minimum) return 0;
  if ((header_flags & 1u) == 0u) score -= 35; /* Sec-Fetch-Site */
  if ((header_flags & 2u) == 0u) score -= 20; /* Origin */
  if ((header_flags & 4u) == 0u) score -= 25; /* application/jend */

  if (pressure > 10u) score -= (int32_t)((pressure - 10u) * 3u);
  if (previous_failures > 0u) score -= (int32_t)(previous_failures * 5u);
  if (known_device) score += 8;

  if (score < 0) score = 0;
  if (score > 100) score = 100;
  return score;
}

__attribute__((visibility("default"))) uint32_t jend_guard_allow(
  uint32_t action,
  uint32_t age_ms,
  uint32_t pressure,
  uint32_t known_device,
  uint32_t header_flags,
  uint32_t previous_failures
) {
  return jend_guard_score(action, age_ms, pressure, known_device, header_flags, previous_failures) >= 55 ? 1u : 0u;
}
