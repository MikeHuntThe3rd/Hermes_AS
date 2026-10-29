use crate::types::Intermediate;

pub struct Pki { pub intermediates: Vec<Intermediate> }

impl Pki {
    pub fn get_im_key(&self, now: i64) -> Option<&Intermediate> {
        self.intermediates.iter()
            .filter(|i| i.active && i.not_before <= now && now < i.not_after)
            .max_by_key(|i| i.not_before)
    }
}
