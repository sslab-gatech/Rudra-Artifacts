use std::ptr;

// A container type that implements Send and Sync for all types, allowing them
// to be sent an used across thread boundaries incorrectly.
pub struct Container<T> {
    pub inner: T,
}

unsafe impl<T> Sync for Container<T> {}
unsafe impl<T> Send for Container<T> {}

// A function that applies a mapping function on a mutable reference.
pub fn map_reference<T, F>(value: &mut T, f: F)
where
    F: Fn(T) -> T,
{
    unsafe {
        // Read manually from the pointer to bypass the lifetime.
        let deref_value = ptr::read(value);
        // Invoke the mapping function, which can potentially panic and cause
        // the deref_value to become double-freed.
        let mapped_value = f(deref_value);
        ptr::write(value, mapped_value);
    }
}


// Some basic unit tests to ensure that the testing code works.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_container_can_contain_items() {
        let container = Container { inner: 200 };
        assert_eq!(container.inner, 200);
    }

    #[test]
    fn mapping_works() {
        let mut int_value = 2;
        map_reference(&mut int_value, |x| x + 1);
        assert_eq!(int_value, 3);
    }
}
