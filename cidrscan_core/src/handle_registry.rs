use crate::{errors::ErrorCode, PatriciaTree};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};

/// Handle ID type - safer than raw pointers
pub type HandleId = u64;

/// Global handle registry for managing PatriciaTree instances
struct HandleRegistry {
    handles: Mutex<HashMap<HandleId, Box<PatriciaTree>>>,
    next_id: AtomicU64,
}

impl HandleRegistry {
    fn new() -> Self {
        Self {
            handles: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1), // Start from 1, reserve 0 for null/invalid
        }
    }

    /// Register a new PatriciaTree and return its handle ID
    fn register(&self, tree: PatriciaTree) -> HandleId {
        let handle_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut handles = self.handles.lock().unwrap();
        handles.insert(handle_id, Box::new(tree));
        handle_id
    }

    /// Get a reference to a PatriciaTree by handle ID
    fn get(&self, handle_id: HandleId) -> Result<std::sync::MutexGuard<'_, HashMap<HandleId, Box<PatriciaTree>>>, ErrorCode> {
        if handle_id == 0 {
            return Err(ErrorCode::InvalidHandle);
        }
        
        self.handles.lock()
            .map_err(|_| ErrorCode::InvalidHandle)
    }

    /// Remove a PatriciaTree from the registry
    fn unregister(&self, handle_id: HandleId) -> Result<(), ErrorCode> {
        if handle_id == 0 {
            return Err(ErrorCode::InvalidHandle);
        }
        
        let mut handles = self.handles.lock()
            .map_err(|_| ErrorCode::InvalidHandle)?;
        
        if handles.remove(&handle_id).is_some() {
            Ok(())
        } else {
            Err(ErrorCode::InvalidHandle)
        }
    }
}

static REGISTRY: OnceLock<HandleRegistry> = OnceLock::new();

fn get_registry() -> &'static HandleRegistry {
    REGISTRY.get_or_init(HandleRegistry::new)
}

/// Register a new PatriciaTree and return its handle ID
pub fn register_handle(tree: PatriciaTree) -> HandleId {
    get_registry().register(tree)
}

/// Execute a function with a reference to the PatriciaTree identified by handle_id
pub fn with_handle<T, F>(handle_id: HandleId, f: F) -> Result<T, ErrorCode>
where
    F: FnOnce(&PatriciaTree) -> T,
{
    let handles = get_registry().get(handle_id)?;
    match handles.get(&handle_id) {
        Some(tree) => Ok(f(tree)),
        None => Err(ErrorCode::InvalidHandle),
    }
}

/// Execute a function with a mutable reference to the PatriciaTree identified by handle_id
pub fn with_handle_mut<T, F>(handle_id: HandleId, f: F) -> Result<T, ErrorCode>
where
    F: FnOnce(&mut PatriciaTree) -> T,
{
    let mut handles = get_registry().get(handle_id)?;
    match handles.get_mut(&handle_id) {
        Some(tree) => Ok(f(tree)),
        None => Err(ErrorCode::InvalidHandle),
    }
}

/// Unregister and drop a PatriciaTree
pub fn unregister_handle(handle_id: HandleId) -> Result<(), ErrorCode> {
    get_registry().unregister(handle_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_registry() {
        // This would need a mock PatriciaTree for proper testing
        // For now, just test the basic registry functionality
        let registry = HandleRegistry::new();
        
        // Test invalid handle
        assert!(registry.get(0).is_err());
        assert!(registry.unregister(999).is_err());
    }
}
