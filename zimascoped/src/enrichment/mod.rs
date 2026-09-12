//! Offline IP enrichment with a bounded lookup cache.
//!
//! Collection never depends on this module: a missing or stale database only
//! means profiles carry scope classification without geographic fields.

pub(crate) mod database;

use std::{net::IpAddr, num::NonZeroUsize, path::Path, sync::Arc, time::SystemTime};

use anyhow::{Context, Result};
use hashlink::LinkedHashMap;
use zimascope_common::model::{AddressScope, IpProfile};

pub(crate) use database::GeoIpDatabase;

/// Default number of cached IP profiles.
pub const DEFAULT_CACHE_CAPACITY: usize = 16_384;

/// Counters and database state for health reporting (PRD 15).
#[derive(Clone, Debug, Default)]
pub struct EnrichmentStats {
    pub database_version: Option<Box<str>>,
    pub database_loaded_at: Option<SystemTime>,
    pub database_index_nodes: usize,
    pub lookups: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub database_lookups: u64,
    pub database_lookup_failures: u64,
    pub local_addresses: u64,
    pub enriched_addresses: u64,
    pub unknown_addresses: u64,
}

/// Enriches addresses and caches profiles per IP.
pub struct Enricher {
    database: Option<GeoIpDatabase>,
    database_loaded_at: Option<SystemTime>,
    cache: LinkedHashMap<IpAddr, Arc<IpProfile>>,
    cache_capacity: NonZeroUsize,
    stats: EnrichmentStats,
}

impl Enricher {
    pub fn new(cache_capacity: NonZeroUsize) -> Self {
        Self {
            database: None,
            database_loaded_at: None,
            cache: LinkedHashMap::new(),
            cache_capacity,
            stats: EnrichmentStats::default(),
        }
    }

    /// Loads a database from `path` and replaces the active snapshot.
    pub fn load_database(&mut self, path: &Path) -> Result<()> {
        let database = GeoIpDatabase::load(path)
            .with_context(|| format!("load GeoIP database {}", path.display()))?;
        self.set_database(database);
        Ok(())
    }

    pub fn set_database(&mut self, database: GeoIpDatabase) {
        self.database_loaded_at = Some(SystemTime::now());
        self.database = Some(database);
        self.cache.clear();
    }

    pub fn database(&self) -> Option<&GeoIpDatabase> {
        self.database.as_ref()
    }

    pub fn stats(&self) -> EnrichmentStats {
        let mut stats = self.stats.clone();
        if let Some(database) = &self.database {
            stats.database_version = Some(database.version().into());
            stats.database_index_nodes = database.index_node_count();
            stats.database_loaded_at = self.database_loaded_at;
        }
        stats
    }

    /// Returns the profile for `address`, consulting the cache first.
    pub fn profile(&mut self, address: IpAddr) -> Arc<IpProfile> {
        self.stats.lookups = self.stats.lookups.saturating_add(1);

        if let Some(profile) = self.cache.get(&address) {
            self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
            return Arc::clone(profile);
        }
        self.stats.cache_misses = self.stats.cache_misses.saturating_add(1);

        let scope = AddressScope::classify(address);
        let (record, database_version) = if scope.is_public() {
            let database_version = self
                .database
                .as_ref()
                .map(|database| Box::<str>::from(database.version()));
            let record = if let Some(database) = &self.database {
                self.stats.database_lookups = self.stats.database_lookups.saturating_add(1);
                match database.lookup(address) {
                    Ok(record) => record,
                    Err(_) => {
                        self.stats.database_lookup_failures =
                            self.stats.database_lookup_failures.saturating_add(1);
                        None
                    }
                }
            } else {
                None
            };
            (record, database_version)
        } else {
            self.stats.local_addresses = self.stats.local_addresses.saturating_add(1);
            (None, None)
        };

        if scope.is_public() {
            if record.is_some() {
                self.stats.enriched_addresses = self.stats.enriched_addresses.saturating_add(1);
            } else {
                self.stats.unknown_addresses = self.stats.unknown_addresses.saturating_add(1);
            }
        }

        let profile = Arc::new(IpProfile {
            address,
            scope,
            country: record.as_ref().and_then(|record| record.country.clone()),
            region: record.as_ref().and_then(|record| record.region.clone()),
            city_approximate: record
                .as_ref()
                .and_then(|record| record.city_approximate.clone()),
            asn: record.as_ref().and_then(|record| record.asn),
            organization: record
                .as_ref()
                .and_then(|record| record.organization.clone()),
            database_version,
            enriched_at: SystemTime::now(),
        });

        self.insert_cache(address, Arc::clone(&profile));
        profile
    }

    fn insert_cache(&mut self, address: IpAddr, profile: Arc<IpProfile>) {
        if self.cache.len() >= self.cache_capacity.get() {
            self.cache.pop_front();
        }
        self.cache.insert(address, profile);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::database::test_database;

    fn capacity() -> NonZeroUsize {
        NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).expect("non-zero")
    }

    fn database() -> GeoIpDatabase {
        test_database()
    }

    #[test]
    fn enriches_public_addresses_from_the_database() {
        let mut enricher = Enricher::new(capacity());
        enricher.set_database(database());

        let profile = enricher.profile("8.8.8.8".parse().unwrap());

        assert_eq!(profile.scope, AddressScope::Public);
        assert_eq!(profile.country.as_deref(), Some("US"));
        assert_eq!(profile.region.as_deref(), Some("California"));
        assert_eq!(profile.city_approximate.as_deref(), Some("Mountain View"));
        assert_eq!(profile.asn, Some(15169));
        assert_eq!(profile.organization.as_deref(), Some("Google LLC"));
        assert_eq!(
            profile.database_version.as_deref(),
            Some("ZimaScope-Test@1788739200")
        );

        let stats = enricher.stats();
        assert!(stats.database_index_nodes > 0);
        assert_eq!(stats.enriched_addresses, 1);
        assert_eq!(stats.unknown_addresses, 0);
    }

    #[test]
    fn unknown_public_addresses_keep_only_scope() {
        let mut enricher = Enricher::new(capacity());
        enricher.set_database(database());

        let profile = enricher.profile("1.1.1.1".parse().unwrap());

        assert_eq!(profile.scope, AddressScope::Public);
        assert!(profile.country.is_none());
        assert!(profile.asn.is_none());
        assert_eq!(
            profile.database_version.as_deref(),
            Some("ZimaScope-Test@1788739200")
        );
        assert_eq!(enricher.stats().unknown_addresses, 1);
    }

    #[test]
    fn local_addresses_are_classified_without_database_queries() {
        let mut enricher = Enricher::new(capacity());
        enricher.set_database(database());

        let profile = enricher.profile("192.168.1.10".parse().unwrap());

        assert_eq!(profile.scope, AddressScope::Private);
        assert!(profile.database_version.is_none());
        assert!(profile.country.is_none());

        let stats = enricher.stats();
        assert_eq!(stats.local_addresses, 1);
        assert_eq!(stats.database_lookups, 0);
    }

    #[test]
    fn collection_works_without_a_database() {
        let mut enricher = Enricher::new(capacity());

        let profile = enricher.profile("8.8.8.8".parse().unwrap());

        assert_eq!(profile.scope, AddressScope::Public);
        assert!(profile.country.is_none());
        assert!(profile.database_version.is_none());
        assert_eq!(enricher.stats().database_index_nodes, 0);
    }

    #[test]
    fn profiles_are_cached() {
        let mut enricher = Enricher::new(capacity());
        enricher.set_database(database());

        let first = enricher.profile("8.8.8.8".parse().unwrap());
        let second = enricher.profile("8.8.8.8".parse().unwrap());

        assert!(Arc::ptr_eq(&first, &second));
        let stats = enricher.stats();
        assert_eq!(stats.lookups, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.database_lookups, 1);
    }

    #[test]
    fn cache_is_bounded_by_fifo_eviction() {
        let mut enricher = Enricher::new(NonZeroUsize::new(1).expect("non-zero"));
        enricher.set_database(database());

        let first = enricher.profile("8.8.8.8".parse().unwrap());
        let _second = enricher.profile("1.1.1.1".parse().unwrap());
        let third = enricher.profile("8.8.8.8".parse().unwrap());

        assert!(!Arc::ptr_eq(&first, &third));
        let stats = enricher.stats();
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 3);
    }

    #[test]
    fn replacing_the_database_clears_the_cache() {
        let mut enricher = Enricher::new(capacity());
        enricher.set_database(database());
        let first = enricher.profile("8.8.8.8".parse().unwrap());

        enricher.set_database(database());
        let second = enricher.profile("8.8.8.8".parse().unwrap());

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(enricher.stats().database_lookups, 2);
    }
}
