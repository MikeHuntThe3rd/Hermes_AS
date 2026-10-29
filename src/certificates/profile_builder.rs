use der::asn1::Ia5String;
use uuid::Uuid;
use x509_cert::{builder::{Result, profile::BuilderProfile}, ext::{Extension, pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectAltName, SubjectKeyIdentifier, name::GeneralName}}, name::Name};
use x509_cert::ext::ToExtension;
pub struct HermesProfile {
    pub issuer: Name,      // IntermediateKey.subject
    pub subject: Name,     // CN=<device_id>
    pub user_id: Uuid,
    pub device_id: Uuid,
}

impl BuilderProfile for HermesProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        return self.issuer.clone();
    }

    fn get_subject(&self) -> Name {
        return self.subject.clone();
    }

    fn build_extensions(
        &self,
        spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> Result<std::vec::Vec<x509_cert::ext::Extension>>
    {
        let mut extensions: Vec<Extension> = Vec::new(); 

        extensions.push(AuthorityKeyIdentifier::try_from(issuer_spk)?.to_extension(&tbs.subject(), &extensions)?);
        extensions.push(BasicConstraints {ca: false, path_len_constraint: None}.to_extension(&tbs.subject(), &extensions)?);
        extensions.push(KeyUsage(KeyUsages::DigitalSignature.into()).to_extension(&tbs.subject(), &extensions)?);
        extensions.push(SubjectKeyIdentifier::try_from(spk)?.to_extension(&tbs.subject(), &extensions)?);

        extensions.push(SubjectAltName(vec![
            GeneralName::UniformResourceIdentifier(Ia5String::new(&format!("urn:uuid:{}", self.user_id))?),
            GeneralName::UniformResourceIdentifier(Ia5String::new(&format!("urn:uuid:{}", self.device_id))?),
        ]).to_extension(&tbs.subject(), &extensions)?);

        return Ok(extensions);
    }
}