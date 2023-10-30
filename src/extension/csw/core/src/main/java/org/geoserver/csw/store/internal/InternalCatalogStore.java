/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2012 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.csw.store.internal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.apache.commons.io.FilenameUtils;
import org.geoserver.config.GeoServer;
import org.geoserver.csw.GetRecords;
import org.geoserver.csw.records.RecordDescriptor;
import org.geoserver.csw.store.AbstractCatalogStore;
import org.geoserver.feature.CompositeFeatureCollection;
import org.geoserver.ows.URLMangler.URLType;
import org.geoserver.ows.util.ResponseUtils;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.platform.resource.Resource;
import org.geoserver.security.PropertyFileWatcher;
import org.geoserver.util.IOUtils;
import org.geotools.data.Query;
import org.geotools.data.Transaction;
import org.geotools.feature.FeatureCollection;
import org.geotools.filter.SortByImpl;
import org.geotools.util.logging.Logging;
import org.opengis.feature.Feature;
import org.opengis.feature.type.FeatureType;
import org.opengis.feature.type.Name;
import org.opengis.filter.Filter;
import org.opengis.filter.expression.Expression;
import org.opengis.filter.expression.PropertyName;
import org.opengis.filter.sort.SortBy;
import org.springframework.beans.BeansException;
import org.springframework.beans.FatalBeanException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * Internal Catalog Store Creates a Catalog Store from a GeoServer Catalog instance and a set of
 * Mappings It can map the internal GS catalog data to 1 or more CSW Record Types, based on one
 * mapping per record type
 *
 * @author Niels Charlier
 */
public class InternalCatalogStore extends AbstractCatalogStore implements ApplicationContextAware {

    protected static final Logger LOGGER = Logging.getLogger(InternalCatalogStore.class);

    protected GeoServer geoServer;

    protected Map<String, CatalogStoreMapping> mappings = new HashMap<>();

    protected MultiValuedMap<String, PropertyFileWatcher> watchers = new ArrayListValuedHashMap<>();

    public InternalCatalogStore(GeoServer geoServer) {
        this.geoServer = geoServer;
    }

    /**
     * Get Mapping
     *
     * @return the mapping
     */
    public List<CatalogStoreMapping> getMappings(String typeName) {
        List<CatalogStoreMapping> result = new ArrayList<>();
        for (PropertyFileWatcher watcher : watchers.get(typeName)) {
            String mappingName = FilenameUtils.removeExtension(watcher.getResource().name());
            if (watcher.isModified()) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, String> properties = (Map) watcher.getProperties();
                    CatalogStoreMapping mapping =
                            CatalogStoreMapping.parse(new HashMap<>(properties), mappingName);
                    mappings.put(mappingName, mapping);
                    result.add(mapping);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, e.toString());
                }
            } else {
                result.add(mappings.get(mappingName));
            }
        }
        return result;
    }

    @Override
    public FeatureCollection<FeatureType, Feature> getRecordsInternal(
            RecordDescriptor rd, RecordDescriptor rdOutput, Query q, Transaction t)
            throws IOException {

        List<FeatureCollection<FeatureType, Feature>> results = new ArrayList<>();

        Map<String, String> interpolationProperties = new HashMap<>();

        String baseUrl = (String) q.getHints().get(GetRecords.KEY_BASEURL);
        if (baseUrl != null) {
            interpolationProperties.put(
                    "url.wfs", ResponseUtils.buildURL(baseUrl, "wfs", null, URLType.SERVICE));
            interpolationProperties.put(
                    "url.wms", ResponseUtils.buildURL(baseUrl, "wms", null, URLType.SERVICE));
            interpolationProperties.put(
                    "url.wcs", ResponseUtils.buildURL(baseUrl, "wcs", null, URLType.SERVICE));
            interpolationProperties.put(
                    "url.wmts",
                    ResponseUtils.buildURL(baseUrl, "gwc/service/wmts", null, URLType.SERVICE));
        }

        Collection<CatalogStoreMapping> mappings = getMappings(q.getTypeName());
        Collection<CatalogStoreMapping> outputMappings =
                getMappings(rdOutput.getFeatureDescriptor().getName().getLocalPart());

        int startIndex = 0;
        if (q.getStartIndex() != null) {
            startIndex = q.getStartIndex();
        }

        for (CatalogStoreMapping mapping : mappings) {

            CSWUnmappingFilterVisitor unmapper = new CSWUnmappingFilterVisitor(mapping, rd);

            Filter unmapped = Filter.INCLUDE;
            // unmap filter
            if (q.getFilter() != null && q.getFilter() != Filter.INCLUDE) {
                Filter filter = q.getFilter();
                unmapped = (Filter) filter.accept(unmapper, null);
            }

            // unmap sortby
            SortBy[] unmappedSortBy = null;
            if (q.getSortBy() != null && q.getSortBy().length > 0) {
                unmappedSortBy = new SortBy[q.getSortBy().length];
                for (int i = 0; i < q.getSortBy().length; i++) {
                    SortBy sortby = q.getSortBy()[i];
                    Expression expr = (Expression) sortby.getPropertyName().accept(unmapper, null);

                    if (!(expr instanceof PropertyName)) {
                        throw new IOException(
                                "Sorting on " + sortby.getPropertyName() + " is not supported.");
                    }

                    unmappedSortBy[i] = new SortByImpl((PropertyName) expr, sortby.getSortOrder());
                }
            }

            for (CatalogStoreMapping outputMapping : outputMappings) {
                // we only output mappings with the same name, to avoid duplication of the results
                // or unfiltered content slipping through

                if (outputMapping.getMappingName().equals(mapping.getMappingName())) {

                    if (q.getProperties() != null) {
                        outputMapping = outputMapping.subMapping(q.getProperties(), rdOutput);
                    }

                    results.add(
                            new CatalogStoreFeatureCollection(
                                    startIndex,
                                    q.getMaxFeatures(),
                                    unmappedSortBy,
                                    unmapped,
                                    geoServer.getCatalog(),
                                    outputMapping,
                                    rdOutput,
                                    interpolationProperties));
                }
            }
        }

        if (results.size() == 1) {
            return results.get(0);
        } else {
            return new CompositeFeatureCollection<>(results);
        }
    }

    @Override
    public PropertyName translateProperty(RecordDescriptor rd, Name name) {
        return rd.translateProperty(name);
    }

    private static boolean isMappingFileForType(String fileName, String typeName) {
        if (!"properties".equals(FilenameUtils.getExtension(fileName))) {
            return false;
        }
        fileName = FilenameUtils.removeExtension(fileName);
        return typeName.equals(fileName) || fileName.startsWith(typeName + "-");
    }

    @Override
    public void setApplicationContext(ApplicationContext appContext) throws BeansException {
        // load record descriptors from application context
        for (RecordDescriptor rd : appContext.getBeansOfType(RecordDescriptor.class).values()) {
            support(rd);
        }
        // load mappings
        GeoServerResourceLoader loader = geoServer.getCatalog().getResourceLoader();
        Resource dir = loader.get("csw");
        try {
            for (Name name : descriptorByType.keySet()) {
                String typeName = name.getLocalPart();
                List<Resource> mappingFiles =
                        dir.list().stream()
                                .filter(r -> isMappingFileForType(r.name(), typeName))
                                .collect(Collectors.toList());

                if (mappingFiles.isEmpty()) {
                    Resource newMapping = dir.get(typeName + ".properties");
                    IOUtils.copy(
                            getClass().getResourceAsStream(typeName + ".default.properties"),
                            newMapping.out());
                    mappingFiles.add(newMapping);
                }

                for (Resource mapping : mappingFiles) {
                    PropertyFileWatcher watcher = new PropertyFileWatcher(mapping);
                    watchers.put(typeName, watcher);
                    @SuppressWarnings("unchecked")
                    Map<String, String> properties = (Map) watcher.getProperties();

                    String mappingName = FilenameUtils.removeExtension(mapping.name());

                    mappings.put(
                            mappingName,
                            CatalogStoreMapping.parse(new HashMap<>(properties), mappingName));
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, e.getMessage(), e);
            throw new FatalBeanException(e.getMessage(), e);
        }
    }
}
