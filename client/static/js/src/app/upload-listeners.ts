/** Upload button and custom file-input label wiring. */
export function setupUploadListeners(): void {
  const uploadFileBtn = document.getElementById('upload-file-btn');
  if (uploadFileBtn) {
    uploadFileBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { handleFileUpload } = await import('../files/upload');
      await handleFileUpload();
    });
  }

  const fileInput = document.getElementById('fileInput') as HTMLInputElement | null;
  const fileInputLabel = document.getElementById('fileInputLabel');
  const fileInputName = document.getElementById('fileInputName');
  if (fileInput && fileInputLabel && fileInputName) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        if (fileInput.files.length === 1) {
          fileInputName.textContent = fileInput.files[0].name;
        } else {
          fileInputName.textContent = `${fileInput.files.length} files selected`;
        }
        fileInputLabel.classList.add('has-file');
      } else {
        fileInputName.textContent = '';
        fileInputLabel.classList.remove('has-file');
      }
    });
  }
}
