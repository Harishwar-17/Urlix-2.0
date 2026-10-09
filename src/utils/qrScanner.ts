import jsQR from 'jsqr'

export async function decodeQrFromImageFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const img = new Image()
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas')
          canvas.width = img.width
          canvas.height = img.height
          const ctx = canvas.getContext('2d')
          if (!ctx) {
            return reject(new Error('Canvas 2D rendering context not available.'))
          }
          ctx.drawImage(img, 0, 0)
          const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height)
          const code = jsQR(imgData.data, imgData.width, imgData.height, {
            inversionAttempts: 'attemptBoth',
          })
          if (code && code.data) {
            resolve(code.data.trim())
          } else {
            reject(new Error('No valid QR code pattern detected in the uploaded image.'))
          }
        } catch (err: any) {
          reject(new Error(err.message || 'Failed to process QR image.'))
        }
      }
      img.onerror = () => reject(new Error('Failed to load image file.'))
      img.src = reader.result as string
    }
    reader.onerror = () => reject(new Error('Failed to read image file.'))
    reader.readAsDataURL(file)
  })
}

/**
 * Generates an SVG Data URI representation of a sample phishing QR or legitimate QR
 * for rapid testing without needing an external image upload.
 */
export function getSampleQrTestDataUri(sampleType: 'phish' | 'legit'): string {
  // SVG representations with encoded patterns or simple mock representations
  if (sampleType === 'phish') {
    return 'http://paypal.com@evil-phishing-login.xyz/account/verify'
  }
  return 'https://github.com/explore'
}
