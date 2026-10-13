let ceremonyBusy = false;
function showMessage(text, state = "") {
  message.textContent = text;
  message.dataset.state = state;
}
async function runCeremony(button, action) {
  if (ceremonyBusy) return;
  ceremonyBusy = true;
  const label = button.textContent;
  const controls = [...document.querySelectorAll("button")];
  controls.forEach((control) => (control.disabled = true));
  button.textContent = "Please wait...";
  showMessage("Follow the passkey prompt on your device.");
  try {
    await action();
    button.textContent = "Done";
  } catch (error) {
    const cancelled =
      error?.name === "NotAllowedError" || error?.name === "AbortError";
    showMessage(
      cancelled
        ? "The passkey request was cancelled or timed out. Please try again."
        : error?.message ||
            "We could not complete this request. Please try again.",
      "error",
    );
    button.textContent = label;
    controls.forEach((control) => (control.disabled = false));
    ceremonyBusy = false;
  }
}
