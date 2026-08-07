#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownRange {
    pub start_id: u64,
    pub end_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gap {
    pub after_id: u64,
    pub before_id: u64,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct RangeSet {
    ranges: Vec<KnownRange>,
}

#[derive(Debug, thiserror::Error)]
pub enum RangeError {
    #[error("a complete range cannot end before it starts")]
    Reversed,
}

impl RangeSet {
    #[must_use]
    pub fn ranges(&self) -> &[KnownRange] {
        &self.ranges
    }

    /// Records an interval the server has proven complete.
    ///
    /// Snowflakes are not assumed to be numerically adjacent. Callers merge
    /// ranges only by supplying an overlapping server-confirmed interval.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::Reversed`] when `end_id` precedes `start_id`.
    pub fn include_complete(&mut self, start_id: u64, end_id: u64) -> Result<(), RangeError> {
        if end_id < start_id {
            return Err(RangeError::Reversed);
        }

        let mut candidate = KnownRange { start_id, end_id };
        let mut merged = Vec::with_capacity(self.ranges.len() + 1);
        let mut inserted = false;
        for current in self.ranges.drain(..) {
            if current.end_id < candidate.start_id {
                merged.push(current);
            } else if candidate.end_id < current.start_id {
                if !inserted {
                    merged.push(candidate);
                    inserted = true;
                }
                merged.push(current);
            } else {
                candidate.start_id = candidate.start_id.min(current.start_id);
                candidate.end_id = candidate.end_id.max(current.end_id);
            }
        }
        if !inserted {
            merged.push(candidate);
        }
        self.ranges = merged;
        Ok(())
    }

    /// Records a gateway message. `contiguous_with_newest` must come from the
    /// gateway/session ordering contract, never from snowflake arithmetic.
    ///
    /// # Errors
    ///
    /// Propagates [`RangeError`] if the resulting complete interval is invalid.
    pub fn observe_live(
        &mut self,
        message_id: u64,
        contiguous_with_newest: bool,
    ) -> Result<(), RangeError> {
        if self
            .ranges
            .iter()
            .any(|range| (range.start_id..=range.end_id).contains(&message_id))
        {
            return Ok(());
        }

        if contiguous_with_newest
            && let Some(newest) = self.ranges.last_mut()
            && message_id > newest.end_id
        {
            newest.end_id = message_id;
            return Ok(());
        }
        self.include_complete(message_id, message_id)
    }

    #[must_use]
    pub fn gaps(&self) -> Vec<Gap> {
        self.ranges
            .windows(2)
            .map(|pair| Gap {
                after_id: pair[0].end_id,
                before_id: pair[1].start_id,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_server_windows_merge() {
        let mut set = RangeSet::default();
        set.include_complete(1_000, 1_500).unwrap();
        set.include_complete(2_000, 2_400).unwrap();
        set.include_complete(1_400, 2_100).unwrap();
        assert_eq!(
            set.ranges(),
            &[KnownRange {
                start_id: 1_000,
                end_id: 2_400
            }]
        );
    }

    #[test]
    fn disconnected_live_event_opens_a_gap() {
        let mut set = RangeSet::default();
        set.include_complete(1_000, 1_500).unwrap();
        set.observe_live(2_000, false).unwrap();
        assert_eq!(
            set.gaps(),
            vec![Gap {
                after_id: 1_500,
                before_id: 2_000
            }]
        );
    }

    #[test]
    fn ordered_live_event_extends_the_newest_range() {
        let mut set = RangeSet::default();
        set.include_complete(1_000, 1_500).unwrap();
        set.observe_live(2_000, true).unwrap();
        assert_eq!(set.ranges()[0].end_id, 2_000);
        assert!(set.gaps().is_empty());
    }

    #[test]
    fn numeric_adjacency_is_not_inferred() {
        let mut set = RangeSet::default();
        set.include_complete(10, 20).unwrap();
        set.include_complete(21, 30).unwrap();
        assert_eq!(set.ranges().len(), 2);
    }
}
