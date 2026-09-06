/**
 * Abort helpers.
 *
 * `isAborted` exists for a specific reason beyond brevity: writing `signal?.aborted === true` twice in
 * one function makes TypeScript narrow the property to `false | undefined` after the first check and
 * reject the second as unreachable. That narrowing is simply wrong here — the whole point of the second
 * check is that an `await` happened in between and the signal may have fired during it. Reading the
 * value through a function call keeps the check honest.
 */
export function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}
