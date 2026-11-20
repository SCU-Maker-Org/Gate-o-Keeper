const link = document.getElementById("share");
if (link) {
  history.replaceState(null, "", link.value);
  const copy = document.getElementById("copy");
  copy.hidden = false;
  copy.addEventListener("click", async () => {
    const feedback = document.getElementById("feedback");
    try {
      await navigator.clipboard.writeText(link.value);
      feedback.textContent = "链接已复制。";
    } catch {
      link.select();
      feedback.textContent = "请使用系统复制功能。";
    }
  });
}
const form = document.querySelector("#unlock[data-auto]");
if (form && document.visibilityState === "visible" && !document.prerendering) {
  form.requestSubmit();
}
