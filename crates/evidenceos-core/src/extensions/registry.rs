use std::collections::HashMap;
use std::sync::Arc;

use crate::extensions::cost_model::CostModel;
use crate::extensions::e_process::EProcess;
use crate::extensions::nullspec::NullSpec;

pub struct ExtensionRegistry {
    nullspecs: HashMap<&'static str, Arc<dyn NullSpec>>,
    cost_models: HashMap<&'static str, Arc<dyn CostModel>>,
    e_processes: HashMap<&'static str, Arc<dyn EProcess>>,
}

impl ExtensionRegistry {
    pub fn default_registry() -> Self {
        // Register one default entry per trait:
        // nullspec: "permutation_default_v1" (stub)
        // cost_model: "log2_alphabet" (stub)
        // e_process: "sequential_lr_default" (stub)
        todo!("wire up defaults")
    }

    pub fn get_nullspec(&self, id: &str) -> Option<Arc<dyn NullSpec>> {
        self.nullspecs.get(id).cloned()
    }

    pub fn get_cost_model(&self, id: &str) -> Option<Arc<dyn CostModel>> {
        self.cost_models.get(id).cloned()
    }

    pub fn get_e_process(&self, id: &str) -> Option<Arc<dyn EProcess>> {
        self.e_processes.get(id).cloned()
    }
}
