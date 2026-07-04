/// Platform abstraction for clipboard operations.
pub trait ClipboardProvider {
    /// Copy text to the system clipboard.
    fn copy_to_clipboard(&mut self, text: &str) -> Result<(), String>;
    /// Clear the clipboard (set empty).
    fn clear_clipboard(&mut self) -> Result<(), String>;
    /// Check if clipboard is supported on this platform.
    fn is_supported(&self) -> bool;
}

/// macOS clipboard provider using arboard.
#[cfg(target_os = "macos")]
pub struct MacClipboard {
    inner: arboard::Clipboard,
}

#[cfg(target_os = "macos")]
impl MacClipboard {
    pub fn new() -> Result<Self, String> {
        let inner =
            arboard::Clipboard::new().map_err(|e| format!("Cannot initialize clipboard: {}", e))?;
        Ok(MacClipboard { inner })
    }
}

#[cfg(target_os = "macos")]
impl ClipboardProvider for MacClipboard {
    fn copy_to_clipboard(&mut self, text: &str) -> Result<(), String> {
        self.inner
            .set_text(text)
            .map_err(|e| format!("Clipboard error: {}", e))
    }

    fn clear_clipboard(&mut self) -> Result<(), String> {
        self.inner
            .set_text("")
            .map_err(|e| format!("Clipboard error: {}", e))
    }

    fn is_supported(&self) -> bool {
        true
    }
}

/// Windows clipboard provider using arboard.
#[cfg(target_os = "windows")]
pub struct WindowsClipboard {
    inner: arboard::Clipboard,
}

#[cfg(target_os = "windows")]
impl WindowsClipboard {
    pub fn new() -> Result<Self, String> {
        let inner =
            arboard::Clipboard::new().map_err(|e| format!("Cannot initialize clipboard: {}", e))?;
        Ok(WindowsClipboard { inner })
    }
}

#[cfg(target_os = "windows")]
impl ClipboardProvider for WindowsClipboard {
    fn copy_to_clipboard(&mut self, text: &str) -> Result<(), String> {
        self.inner
            .set_text(text)
            .map_err(|e| format!("Clipboard error: {}", e))
    }

    fn clear_clipboard(&mut self) -> Result<(), String> {
        self.inner
            .set_text("")
            .map_err(|e| format!("Clipboard error: {}", e))
    }

    fn is_supported(&self) -> bool {
        true
    }
}

/// Linux clipboard provider using arboard.
#[cfg(target_os = "linux")]
pub struct LinuxClipboard {
    inner: arboard::Clipboard,
}

#[cfg(target_os = "linux")]
impl LinuxClipboard {
    pub fn new() -> Result<Self, String> {
        let inner =
            arboard::Clipboard::new().map_err(|e| format!("Cannot initialize clipboard: {}", e))?;
        Ok(LinuxClipboard { inner })
    }
}

#[cfg(target_os = "linux")]
impl ClipboardProvider for LinuxClipboard {
    fn copy_to_clipboard(&mut self, text: &str) -> Result<(), String> {
        self.inner
            .set_text(text)
            .map_err(|e| format!("Clipboard error: {}", e))
    }

    fn clear_clipboard(&mut self) -> Result<(), String> {
        self.inner
            .set_text("")
            .map_err(|e| format!("Clipboard error: {}", e))
    }

    fn is_supported(&self) -> bool {
        true
    }
}

/// Unsupported platform clipboard (no-op) for platforms without arboard support.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub struct UnsupportedClipboard;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
impl UnsupportedClipboard {
    pub fn new() -> Result<Self, String> {
        Ok(UnsupportedClipboard)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
impl ClipboardProvider for UnsupportedClipboard {
    fn copy_to_clipboard(&mut self, _text: &str) -> Result<(), String> {
        Err("Clipboard unsupported on this platform.".to_string())
    }

    fn clear_clipboard(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn is_supported(&self) -> bool {
        false
    }
}

/// Factory to create the platform-appropriate clipboard.
pub fn create_clipboard() -> Result<Box<dyn ClipboardProvider>, String> {
    #[cfg(target_os = "macos")]
    {
        MacClipboard::new().map(|c| Box::new(c) as Box<dyn ClipboardProvider>)
    }
    #[cfg(target_os = "linux")]
    {
        LinuxClipboard::new().map(|c| Box::new(c) as Box<dyn ClipboardProvider>)
    }
    #[cfg(target_os = "windows")]
    {
        WindowsClipboard::new().map(|c| Box::new(c) as Box<dyn ClipboardProvider>)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        UnsupportedClipboard::new().map(|c| Box::new(c) as Box<dyn ClipboardProvider>)
    }
}
