//! Media types of signed files, by extension.

/// The media type of a file by its extension (case-insensitive); application/octet-stream for anything else.
pub fn mime_type_of(file_name: &str) -> &'static str {
    let extension = match file_name.rsplit_once('.') {
        Some((stem, extension)) if !extension.contains('/') && !stem.ends_with('/') => extension.to_lowercase(),
        _ => String::new(),
    };
    match extension.as_str() {
        "pdf" => "application/pdf",
        "xml" => "application/xml",
        "txt" => "text/plain",
        "json" => "application/json",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_types_follow_the_extension() {
        assert_eq!(mime_type_of("contract.PDF"), "application/pdf");
        assert_eq!(mime_type_of("annex/табл.csv"), "application/octet-stream");
        assert_eq!(mime_type_of("dir.d/README"), "application/octet-stream");
        assert_eq!(mime_type_of("заява.txt"), "text/plain");
    }
}
