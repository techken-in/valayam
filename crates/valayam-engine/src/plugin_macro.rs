//! Declarative macro for generating ScanPlugin adapters from existing executors.
//!
//! Used by all `impl_scan_plugin!` call sites in `valayam-core` and `valayam-core-net`.
//! Eliminates ~2600 lines of boilerplate. Each plugin is defined in ~5 lines.
//! Generated via `#[macro_export]` — available at crate root.

/// Generate a `ScanPlugin` implementation that wraps an existing feature executor.
#[macro_export]
macro_rules! impl_scan_plugin {
    // Variant 1: Stateless plugin, no dependencies
    (
        $struct_name:ident,
        $name:expr,
        $field:ident,
        |$ctx:ident, $template:ident, $ftx:ident| $body:block
    ) => {
        pub struct $struct_name;

        impl $struct_name {
            pub fn new() -> Self { Self }
        }

        #[async_trait::async_trait]
        impl $crate::traits::ScanPlugin for $struct_name {
            fn name(&self) -> &str { $name }

            fn is_applicable(
                &self,
                template: &valayam_models::templates::schema::VulnerabilityTemplate,
            ) -> bool {
                !template.$field.is_empty()
            }

            async fn execute(
                &self,
                $ctx: &$crate::traits::ScanContext,
            ) -> $crate::traits::PluginOutcome {
                let $template = &$ctx.template;
                let $ftx = &$ctx.finding_tx;
                $body
            }
        }
    };

    // Variant 2: Stateless plugin with dependencies
    (
        $struct_name:ident,
        $name:expr,
        $field:ident,
        depends_on: $deps:expr,
        |$ctx:ident, $template:ident, $ftx:ident| $body:block
    ) => {
        pub struct $struct_name;

        impl $struct_name {
            pub fn new() -> Self { Self }
        }

        #[async_trait::async_trait]
        impl $crate::traits::ScanPlugin for $struct_name {
            fn name(&self) -> &str { $name }

            fn is_applicable(
                &self,
                template: &valayam_models::templates::schema::VulnerabilityTemplate,
            ) -> bool {
                !template.$field.is_empty()
            }

            fn depends_on(&self) -> &[&'static str] { $deps }

            async fn execute(
                &self,
                $ctx: &$crate::traits::ScanContext,
            ) -> $crate::traits::PluginOutcome {
                let $template = &$ctx.template;
                let $ftx = &$ctx.finding_tx;
                $body
            }
        }
    };

    // Variant 3: Stateful plugin (holds Arc<Client> etc.)
    (
        $struct_name:ident,
        $name:expr,
        $field:ident,
        state: { $($sfield:ident : $stype:ty),* },
        |$self:ident, $ctx:ident, $template:ident, $ftx:ident| $body:block
    ) => {
        pub struct $struct_name {
            $(pub $sfield: $stype),*
        }

        impl $struct_name {
            pub fn new($($sfield: $stype),*) -> Self {
                Self { $($sfield),* }
            }
        }

        #[async_trait::async_trait]
        impl $crate::traits::ScanPlugin for $struct_name {
            fn name(&self) -> &str { $name }

            fn is_applicable(
                &self,
                template: &valayam_models::templates::schema::VulnerabilityTemplate,
            ) -> bool {
                !template.$field.is_empty()
            }

            async fn execute(
                &$self,
                $ctx: &$crate::traits::ScanContext,
            ) -> $crate::traits::PluginOutcome {
                let $template = &$ctx.template;
                let $ftx = &$ctx.finding_tx;
                $body
            }
        }
    };
}
