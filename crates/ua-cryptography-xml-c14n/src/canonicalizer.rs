//! Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 of a document or an element subtree.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::rc::Rc;

use roxmltree::Attribute;
use roxmltree::Node;

use crate::algorithm::Algorithm;
use crate::escape::push_escaped_attribute;
use crate::escape::push_escaped_text;

/// The namespace of the `xml:` prefix.
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
/// The `xml` prefix, bound by definition and never rendered.
const XML_PREFIX: &str = "xml";
/// The prefix of the default namespace.
const DEFAULT_PREFIX: &str = "";
/// The namespace URI of an unprefixed attribute: none, sorted first.
const NO_NAMESPACE: &str = "";
/// The name of the default namespace in an InclusiveNamespaces PrefixList.
const DEFAULT_PREFIX_TOKEN: &str = "#default";

/// Prefix → namespace URI.
type Scope<'a> = BTreeMap<&'a str, &'a str>;

/// Canonicalizes a document (`document.root()`) or an element with its descendants by `algorithm`.
///
/// An element is canonicalized in its document context: the namespaces in scope come from its ancestors too, and
/// for inclusive canonicalization so do their `xml:*` attributes. `inclusive_prefixes` is the InclusiveNamespaces
/// PrefixList of exclusive canonicalization (`#default` names the default namespace); inclusive canonicalization
/// ignores it. `excluded` and its descendants are left out (the enveloped-signature transform).
///
/// # Panics
/// If `node` is neither the document root nor an element.
pub fn canonicalize<'a, 'input>(
    node: Node<'a, 'input>,
    algorithm: Algorithm,
    inclusive_prefixes: &[&str],
    excluded: Option<Node<'a, 'input>>,
) -> Vec<u8> {
    assert!(
        node.is_root() || node.is_element(),
        "only a document or an element can be canonicalized"
    );
    let mut writer = Writer {
        is_exclusive: algorithm.is_exclusive(),
        keeps_comments: algorithm.keeps_comments(),
        inclusive_prefixes: inclusive_prefixes
            .iter()
            .map(|prefix| prefix_of_token(prefix).to_owned())
            .collect(),
        excluded,
        output: String::new(),
    };
    if node.is_root() {
        writer.write_document(node);
    } else {
        writer.write_subtree(node);
    }
    writer.output.into_bytes()
}

/// One step of the depth-first walk; an explicit stack keeps deep documents off the call stack.
enum Step<'a, 'input> {
    Open {
        element: Node<'a, 'input>,
        rendered: Rc<Scope<'a>>,
        is_apex: bool,
    },
    Close {
        name: &'input str,
    },
    Leaf(Node<'a, 'input>),
}

/// An attribute as it is written: sorted by namespace URI, then local name (C14N 1.0, 2.2).
struct OutputAttribute<'a> {
    namespace: &'a str,
    local_name: &'a str,
    qualified_name: &'a str,
    value: &'a str,
}

struct Writer<'a, 'input> {
    is_exclusive: bool,
    keeps_comments: bool,
    inclusive_prefixes: Vec<String>,
    excluded: Option<Node<'a, 'input>>,
    output: String,
}

impl<'a, 'input> Writer<'a, 'input> {
    // Comments and PIs outside the document element are separated from it by a line feed (C14N 1.0, 2.1).
    fn write_document(&mut self, root: Node<'a, 'input>) {
        let mut is_after_document_element = false;
        let excluded = self.excluded;
        for child in root.children().filter(|child| Some(*child) != excluded) {
            if child.is_element() {
                self.write_subtree(child);
                is_after_document_element = true;
            } else if (child.is_comment() && self.keeps_comments) || child.is_pi() {
                if is_after_document_element {
                    self.output.push('\n');
                }
                self.write_leaf(child);
                if !is_after_document_element {
                    self.output.push('\n');
                }
            }
        }
    }

    fn write_subtree(&mut self, apex: Node<'a, 'input>) {
        let mut steps = vec![Step::Open {
            element: apex,
            rendered: Rc::new(empty_context()),
            is_apex: true,
        }];
        while let Some(step) = steps.pop() {
            match step {
                Step::Open {
                    element,
                    rendered,
                    is_apex,
                } => {
                    let (name, child_rendered) = self.write_start_tag(element, &rendered, is_apex);
                    steps.push(Step::Close { name });
                    let excluded = self.excluded;
                    let children = element.children().filter(|child| Some(*child) != excluded);
                    for child in children.collect::<Vec<_>>().into_iter().rev() {
                        steps.push(if child.is_element() {
                            Step::Open {
                                element: child,
                                rendered: Rc::clone(&child_rendered),
                                is_apex: false,
                            }
                        } else {
                            Step::Leaf(child)
                        });
                    }
                }
                Step::Close { name } => {
                    self.output.push_str("</");
                    self.output.push_str(name);
                    self.output.push('>');
                }
                Step::Leaf(node) => self.write_leaf(node),
            }
        }
    }

    // Writes `<name xmlns… attributes…>`; returns the name and the namespaces rendered for the children.
    fn write_start_tag(
        &mut self,
        element: Node<'a, 'input>,
        rendered: &Rc<Scope<'a>>,
        is_apex: bool,
    ) -> (&'input str, Rc<Scope<'a>>) {
        let name = qualified_name_of(element);
        let in_scope = in_scope_of(element);
        let namespaces = self.select_namespaces_to_render(element, name, &in_scope, rendered);
        let attributes = self.select_attributes(element, is_apex);

        self.output.push('<');
        self.output.push_str(name);
        for (prefix, uri) in &namespaces {
            self.output.push_str(" xmlns");
            if !prefix.is_empty() {
                self.output.push(':');
                self.output.push_str(prefix);
            }
            self.output.push_str("=\"");
            push_escaped_attribute(&mut self.output, uri);
            self.output.push('"');
        }
        for attribute in &attributes {
            self.output.push(' ');
            self.output.push_str(attribute.qualified_name);
            self.output.push_str("=\"");
            push_escaped_attribute(&mut self.output, attribute.value);
            self.output.push('"');
        }
        self.output.push('>');

        if namespaces.is_empty() {
            return (name, Rc::clone(rendered));
        }
        let mut child_rendered = Scope::clone(rendered);
        child_rendered.extend(namespaces);
        (name, Rc::new(child_rendered))
    }

    fn write_leaf(&mut self, node: Node<'a, 'input>) {
        if let Some(instruction) = node.pi() {
            self.output.push_str("<?");
            self.output.push_str(instruction.target);
            if let Some(value) = instruction.value.filter(|value| !value.is_empty()) {
                self.output.push(' ');
                self.output.push_str(value);
            }
            self.output.push_str("?>");
            return;
        }
        let Some(text) = node.text() else {
            return;
        };
        if node.is_text() {
            push_escaped_text(&mut self.output, text);
        } else if node.is_comment() && self.keeps_comments {
            self.output.push_str("<!--");
            self.output.push_str(text);
            self.output.push_str("-->");
        }
    }

    // The namespace declarations the element renders, sorted by prefix, the default namespace first.
    fn select_namespaces_to_render(
        &self,
        element: Node<'a, 'input>,
        name: &str,
        in_scope: &Scope<'a>,
        rendered: &Scope<'a>,
    ) -> Vec<(&'a str, &'a str)> {
        let candidates: BTreeSet<&str> = if self.is_exclusive {
            let mut utilized = visibly_utilized_prefixes(element, name);
            utilized.extend(self.inclusive_prefixes.iter().map(String::as_str));
            utilized
        } else {
            in_scope.keys().copied().collect()
        };
        let mut namespaces = Vec::new();
        for candidate in candidates {
            let Some((&prefix, &uri)) = in_scope.get_key_value(candidate) else {
                continue;
            };
            if prefix != XML_PREFIX && is_rendered_anew(prefix, uri, rendered) {
                namespaces.push((prefix, uri));
            }
        }
        namespaces.sort_by(|(left, _), (right, _)| compare_ordinal(left, right));
        namespaces
    }

    // The element's attributes and, at the apex of inclusive canonicalization, the `xml:*` ones it inherits.
    fn select_attributes(&self, element: Node<'a, 'input>, is_apex: bool) -> Vec<OutputAttribute<'a>> {
        let source = element.document().input_text();
        let mut attributes: Vec<OutputAttribute<'a>> = element
            .attributes()
            .map(|attribute| output_attribute_of(source, attribute))
            .collect();
        if !self.is_exclusive && is_apex {
            let inherited = select_inherited_xml_attributes(element, &attributes);
            attributes.extend(inherited);
        }
        attributes.sort_by(|left, right| {
            compare_ordinal(left.namespace, right.namespace)
                .then_with(|| compare_ordinal(left.local_name, right.local_name))
        });
        attributes
    }
}

fn empty_context<'a>() -> Scope<'a> {
    Scope::from([(DEFAULT_PREFIX, "")])
}

// The namespaces in scope at the element, its ancestors' declarations included; no default namespace is "".
fn in_scope_of<'a>(element: Node<'a, '_>) -> Scope<'a> {
    let mut scope = empty_context();
    for namespace in element.namespaces() {
        let prefix = match namespace.name() {
            Some(prefix) => prefix,
            None => DEFAULT_PREFIX,
        };
        scope.insert(prefix, namespace.uri());
    }
    scope
}

// A default namespace is rendered when it differs from the output ancestors' (`xmlns=""` only to undo one);
// a prefix when the output ancestors did not render it with this URI.
fn is_rendered_anew(prefix: &str, uri: &str, rendered: &Scope<'_>) -> bool {
    let current = rendered.get(prefix).copied();
    if prefix.is_empty() {
        return match current {
            Some(current) => current != uri,
            None => !uri.is_empty(),
        };
    }
    current != Some(uri) && !uri.is_empty()
}

// Exclusive C14N 1.0, 3: the element's own prefix (or the default namespace) and the prefixes of its attributes.
fn visibly_utilized_prefixes<'n>(element: Node<'_, 'n>, name: &'n str) -> BTreeSet<&'n str> {
    let mut prefixes = BTreeSet::from([prefix_of(name)]);
    let source = element.document().input_text();
    for attribute in element.attributes() {
        let prefix = prefix_of(attribute_qualified_name(source, &attribute));
        if !prefix.is_empty() {
            prefixes.insert(prefix);
        }
    }
    prefixes
}

// C14N 1.0, 2.4: the `xml:*` attributes of the ancestors, nearest first, unless the apex has its own.
fn select_inherited_xml_attributes<'a>(apex: Node<'a, '_>, own: &[OutputAttribute<'a>]) -> Vec<OutputAttribute<'a>> {
    let source = apex.document().input_text();
    let mut inherited: Vec<OutputAttribute<'a>> = Vec::new();
    for ancestor in apex.ancestors().skip(1).filter(Node::is_element) {
        for attribute in ancestor
            .attributes()
            .filter(|attribute| attribute.namespace() == Some(XML_NAMESPACE))
        {
            let is_overridden = own
                .iter()
                .chain(inherited.iter())
                .any(|present| present.namespace == XML_NAMESPACE && present.local_name == attribute.name());
            if !is_overridden {
                inherited.push(output_attribute_of(source, attribute));
            }
        }
    }
    inherited
}

fn output_attribute_of<'a>(source: &'a str, attribute: Attribute<'a, '_>) -> OutputAttribute<'a> {
    let namespace = match attribute.namespace() {
        Some(namespace) => namespace,
        None => NO_NAMESPACE,
    };
    OutputAttribute {
        namespace,
        local_name: attribute.name(),
        qualified_name: attribute_qualified_name(source, &attribute),
        value: attribute.value(),
    }
}

// The element name as written, prefix included: roxmltree keeps only the namespace URI.
fn qualified_name_of<'input>(element: Node<'_, 'input>) -> &'input str {
    let after_open = &element.document().input_text()[element.range().start + '<'.len_utf8()..];
    take_name(after_open)
}

fn attribute_qualified_name<'input>(source: &'input str, attribute: &Attribute<'_, 'input>) -> &'input str {
    take_name(&source[attribute.range().start..])
}

// A name runs up to white space, `=`, `/` or `>`.
fn take_name(text: &str) -> &str {
    let is_name_end = |character: char| matches!(character, ' ' | '\t' | '\n' | '\r' | '=' | '/' | '>');
    match text.find(is_name_end) {
        Some(end) => &text[..end],
        None => text,
    }
}

fn prefix_of(qualified_name: &str) -> &str {
    match qualified_name.split_once(':') {
        Some((prefix, _)) => prefix,
        None => DEFAULT_PREFIX,
    }
}

fn prefix_of_token(token: &str) -> &str {
    if token == DEFAULT_PREFIX_TOKEN {
        DEFAULT_PREFIX
    } else {
        token
    }
}

// Ordinal order of UTF-16 code units; above U+FFFF it differs from code point order.
fn compare_ordinal(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}
