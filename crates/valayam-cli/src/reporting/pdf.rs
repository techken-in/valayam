use genpdf::{elements, Document, SimplePageDecorator};
use std::fs::File;
use valayam_core::core::result::ScanResult;

pub fn generate_pdf(
    results: &[ScanResult],
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate an enhanced PDF report
    let font_paths = [
        ("./fonts", "Roboto"),
        ("/usr/share/fonts/truetype/dejavu", "DejaVuSans"),
        ("C:\\Windows\\Fonts", "arial"),
        ("/System/Library/Fonts", "Helvetica"),
    ];

    let mut font_family = None;
    for (dir, name) in font_paths {
        if let Ok(ff) = genpdf::fonts::from_files(dir, name, None) {
            font_family = Some(ff);
            break;
        }
    }

    let font_family = match font_family {
        Some(f) => f,
        None => return Err("Could not find any standard fonts on this system. Please provide fonts in ./fonts or use --format json".into()),
    };

    let mut doc = Document::new(font_family);
    doc.set_title("Valayam Enterprise Scan Report");
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(10);
    doc.set_page_decorator(decorator);

    // Cover Page
    doc.push(
        elements::Paragraph::new("Valayam Security Scan Report").aligned(genpdf::Alignment::Center),
    );
    doc.push(elements::Break::new(2));

    doc.push(
        elements::Paragraph::new(format!(
            "Generated at: {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ))
        .aligned(genpdf::Alignment::Center),
    );
    doc.push(elements::Break::new(2));

    // Executive Summary
    doc.push(elements::Paragraph::new("Executive Summary").aligned(genpdf::Alignment::Left));
    doc.push(elements::Break::new(1));

    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for res in results {
        match res.template_severity.to_lowercase().as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => info += 1,
        }
    }

    doc.push(elements::Paragraph::new(format!(
        "Total Findings: {}",
        results.len()
    )));
    doc.push(elements::Paragraph::new(format!(
        "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
        critical, high, medium, low, info
    )));
    doc.push(elements::PageBreak::new());

    // Detailed Findings
    doc.push(elements::Paragraph::new("Detailed Findings").aligned(genpdf::Alignment::Left));
    doc.push(elements::Break::new(1));

    for (i, res) in results.iter().enumerate() {
        doc.push(elements::Paragraph::new(format!(
            "{}. {} ({})",
            i + 1,
            res.template_name,
            res.template_id
        )));
        doc.push(elements::Paragraph::new(format!(
            "Severity: {}",
            res.template_severity.to_uppercase()
        )));
        doc.push(elements::Paragraph::new(format!("Target: {}", res.target)));

        if !res.payload.is_empty() {
            doc.push(elements::Paragraph::new(format!(
                "Matched At: {}",
                res.payload
            )));
        }

        doc.push(elements::Break::new(1));
    }

    let mut file = File::create(output_path)?;
    doc.render(&mut file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pdf_empty_results_system_font() {
        // On a system with fonts, PDF generation should succeed.
        // On a system without fonts (CI), it returns the font error.
        // We just verify it doesn't panic and returns either Ok or a String error.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.pdf");
        let path_str = path.to_str().unwrap();
        match generate_pdf(&[], path_str) {
            Ok(()) => assert!(path.exists()),
            Err(e) => {
                let msg = format!("{}", e);
                assert!(
                    msg.contains("font") || msg.contains("Font"),
                    "Expected font error: {}",
                    msg
                );
            }
        }
    }

    #[test]
    fn test_generate_pdf_invalid_path_returns_err() {
        let result = generate_pdf(&[], "/nonexistent_dir/report.pdf");
        assert!(result.is_err());
    }
}
