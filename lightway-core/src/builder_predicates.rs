/// Extension trait adding useful predicate methods to a builder pattern.
pub trait BuilderPredicates: Sized {
    /// The Error variant for fallible predicates
    type Error;

    /// When `cond` is True call `func` on `Self`
    fn when<F>(self, cond: bool, func: F) -> Self
    where
        F: FnOnce(Self) -> Self,
    {
        if cond { func(self) } else { self }
    }

    /// When `cond` is True call fallible `func` on `Self`
    fn try_when<F>(self, cond: bool, func: F) -> Result<Self, Self::Error>
    where
        F: FnOnce(Self) -> Result<Self, Self::Error>,
    {
        if cond { func(self) } else { Ok(self) }
    }

    /// When `maybe` is Some(_) call `func` on `Self` and the contained value
    fn when_some<F, T>(self, maybe: Option<T>, func: F) -> Self
    where
        F: FnOnce(Self, T) -> Self,
    {
        if let Some(t) = maybe {
            func(self, t)
        } else {
            self
        }
    }

    /// When `maybe` is Some(_) call fallible `func` on `Self` and the contained value
    fn try_when_some<F, T>(self, maybe: Option<T>, func: F) -> Result<Self, Self::Error>
    where
        F: FnOnce(Self, T) -> Result<Self, Self::Error>,
    {
        if let Some(t) = maybe {
            func(self, t)
        } else {
            Ok(self)
        }
    }
}
