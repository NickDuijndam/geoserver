ALTER TABLE public.collection_ogclink
add column "intTest" integer, add column "floatTest" float, add column "booleanTest" boolean, add column "dateTest" date, add column "varcharTest" varchar;
-- data
INSERT INTO collection
("id", "name", "title", "description", "primary", "footprint", "timeStart", "timeEnd", "productCqlFilter", "masked", "eoIdentifier", "eoProductType", "eoPlatform", "eoPlatformSerialIdentifier", "eoInstrument", "eoSensorType", "eoCompositeType", "eoProcessingLevel", "eoOrbitType", "eoSpectralRange", "eoWavelength", "eoSecurityConstraints", "eoDissemination", "eoAcquisitionStation", "license", "assets")
VALUES(17, 'SENTINEL2', 'The Sentinel-2 mission', 'The SENTINEL-2 mission is a land monitoring constellation of two satellites each equipped with a MSI (Multispectral Imager) instrument covering 13 spectral bands providing high resolution optical imagery (i.e., 10m, 20m, 60 m) every 10 days with one satellite and 5 days with two satellites.', NULL, ST_GeomFromText('POLYGON((-179 89,179 89,179 -89,-179 -89,-179 89))', 4326), '2015-07-01 10:20:21.000', '2016-02-26 10:20:21.000', NULL, NULL, 'SENTINEL2', 'S2MSI1C', 'Sentinel-2', 'A', ARRAY['MSI'], 'OPTICAL', NULL, 'Level-1C', 'LEO', NULL, NULL, NULL, NULL, NULL, 'CC-BY-NC-ND-3.0-IGO', '{ "metadata_iso_19139": { "roles": [ "metadata", "iso-19139" ], "href": "https://storage.googleapis.com/open-cogs/stac-examples/sentinel-2-iso-19139.xml", "title": "ISO 19139 metadata", "type": "application/vnd.iso.19139+xml" }}');
INSERT INTO collection
("id", "name", "title", "description", "primary", "footprint", "timeStart", "timeEnd", "productCqlFilter", "masked", "eoIdentifier", "eoProductType", "eoPlatform", "eoPlatformSerialIdentifier", "eoInstrument", "eoSensorType", "eoCompositeType", "eoProcessingLevel", "eoOrbitType", "eoSpectralRange", "eoWavelength", "eoSecurityConstraints", "eoDissemination", "eoAcquisitionStation", "license")
VALUES(32, 'SENTINEL1', 'Sentinel-1 (PEPS)', 'Landsat 8 is an American Earth observation satellite launched on February 11, 2013. It is the eighth satellite in the Landsat program; the seventh to reach orbit successfully. Originally called the Landsat Data Continuity Mission (LDCM), it is a collaboration between NASA and the United States Geological Survey (USGS). The Landsat 8 Operational Land Imager (OLI) collects data from nine spectral bands. Seven of the nine bands are consistent with the Thematic Mapper (TM) and Enhanced Thematic Mapper Plus (ETM+) sensors found on earlier Landsat satellites, providing for compatibility with the historical Landsat data, while also improving measurement capabilities.', NULL, ST_GeomFromText('POLYGON((-179 89,179 89,179 -89,-179 -89,-179 89))', 4326), '2015-02-26 10:20:21.000', NULL , NULL, NULL, 'SENTINEL1', NULL, 'Sentinel-1', NULL, ARRAY['C-SAR'], 'RADAR', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'CC-BY-NC-ND-3.0-IGO');
INSERT INTO collection
("id", "name", "title", "description", "primary", "footprint", "timeStart", "timeEnd", "productCqlFilter", "masked", "eoIdentifier", "eoProductType", "eoPlatform", "eoPlatformSerialIdentifier", "eoInstrument", "eoSensorType", "eoCompositeType", "eoProcessingLevel", "eoOrbitType", "eoSpectralRange", "eoWavelength", "eoSecurityConstraints", "eoDissemination", "eoAcquisitionStation", "license")
VALUES(31, 'LANDSAT8', 'The Landsat-8 mission', 'Landsat 8 is an American Earth observation satellite launched on February 11, 2013. It is the eighth satellite in the Landsat program; the seventh to reach orbit successfully.Originally called the Landsat Data Continuity Mission (LDCM), it is a collaboration between NASA and the United States Geological Survey (USGS). The Landsat 8 Operational Land Imager (OLI) collects data from nine spectral bands. Seven of the nine bands are consistent with the Thematic Mapper (TM) and Enhanced Thematic Mapper Plus (ETM+) sensors found on earlier Landsat satellites, providing for compatibility with the historical Landsat data, while also improving measurement capabilities.', NULL, ST_GeomFromText('POLYGON((-179 89,179 89,179 -89,-179 -89,-179 89))', 4326), '1988-02-26 10:20:21.000', '2013-03-01 10:20:21.000', NULL, NULL, 'LANDSAT8', NULL, '', NULL, ARRAY['OLI', 'TIRS'], 'OPTICAL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'proprietary');
INSERT INTO collection
("id", "name", "title", "description", "primary", "footprint", "timeStart", "timeEnd", "productCqlFilter", "masked", "eoIdentifier", "eoProductType", "eoPlatform", "eoPlatformSerialIdentifier", "eoInstrument", "eoSensorType", "eoCompositeType", "eoProcessingLevel", "eoOrbitType", "eoSpectralRange", "eoWavelength", "eoSecurityConstraints", "eoDissemination", "eoAcquisitionStation", "license")
VALUES(18, 'ATMTEST', 'Atmospheric collection test', 'The sample atmospheric sensor (SAS)', NULL, ST_GeomFromText('POLYGON((-179 89,179 89,179 -89,-179 -89,-179 89))', 4326), '2018-02-26 10:20:21.000', '2018-03-01 10:20:21.000', NULL, NULL, 'SAS1', NULL, '', NULL, ARRAY['SAI1'], 'ATMOSPHERIC', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'various');
INSERT INTO collection
("id", "name", "title", "description", "primary", "footprint", "timeStart", "timeEnd", "productCqlFilter", "masked", "eoIdentifier", "eoProductType", "eoPlatform", "eoPlatformSerialIdentifier", "eoInstrument", "eoSensorType", "eoCompositeType", "eoProcessingLevel", "eoOrbitType", "eoSpectralRange", "eoWavelength", "eoSecurityConstraints", "eoDissemination", "eoAcquisitionStation", "license", "enabled")
VALUES(34, 'DISABLED_COLLECTION', 'A disabled collections', 'Not meant to be shared', NULL, ST_GeomFromText('POLYGON((-179 89,179 89,179 -89,-179 -89,-179 89))', 4326), '2015-07-01 10:20:21.000', '2016-02-26 10:20:21.000', NULL, NULL, 'DISABLED_COLLECTION', 'S2MSI1C', 'Sentinel-2', 'A', ARRAY['MUI'], 'OPTICAL', NULL, 'Level-1C', 'LEO', NULL, NULL, NULL, NULL, NULL, 'CC-BY-NC-ND-3.0-IGO', false);
-- setup sequence to allow new inserts
select setval('collection_id_seq'::regclass, 35);
-- collection ogc links
INSERT INTO public.collection_ogclink
("collection_id", "offering", "method", "code", "type", "href", "intTest", "floatTest", "booleanTest", "dateTest", "varcharTest")
VALUES(17, 'http://www.opengis.net/spec/owc/1.0/req/atom/wms', 'GET', 'GetCapabilities', 'application/xml', '${BASE_URL}/sentinel2/ows?service=wms&version=1.3.0&request=GetCapabilities', 17, 17.1, true, '2017-01-01', 'text17');
INSERT INTO public.collection_ogclink
("collection_id", "offering", "method", "code", "type", "href", "intTest", "floatTest", "booleanTest", "dateTest", "varcharTest")
VALUES(31, 'http://www.opengis.net/spec/owc/1.0/req/atom/wms', 'GET', 'GetCapabilities', 'application/xml', '${BASE_URL}/landsat8/ows?service=wms&version=1.3.0&request=GetCapabilities', 31, 31.1, true, '2031-01-01', 'text31');
INSERT INTO public.collection_ogclink
("collection_id", "offering", "method", "code", "type", "href", "intTest", "floatTest", "booleanTest", "dateTest", "varcharTest")
VALUES(32, 'http://www.opengis.net/spec/owc/1.0/req/atom/wms', 'GET', 'GetCapabilities', 'application/xml', '${BASE_URL}/sentinel1/ows?service=wms&version=1.3.0&request=GetCapabilities', 32, 32.1, true, '2032-01-01', 'text32');
-- collection publishing metadata
INSERT into public.collection_layer
("cid", "workspace", "layer", "separateBands", "bands", "browseBands", "heterogeneousCRS", "mosaicCRS", "defaultLayer")
VALUES(17, 'gs', 'sentinel2', true, 'B01,B02,B03,B04,B05,B06,B07,B08,B09,B10,B11,B12', 'B04,B03,B02', true, 'EPSG:4326', true);
INSERT into public.collection_layer
("cid", "workspace", "layer", "separateBands", "bands", "browseBands", "heterogeneousCRS", "mosaicCRS", "defaultLayer")
VALUES(31, 'gs', 'landsat8-SINGLE', false, null, null, true, 'EPSG:4326', true);
INSERT into public.collection_layer
("cid", "workspace", "layer", "separateBands", "bands", "browseBands", "heterogeneousCRS", "mosaicCRS", "defaultLayer")
VALUES(31, 'gs', 'landsat8-SEPARATE', true, 'B01,B02,B03,B04,B05,B06,B07,B08,B09', 'B04,B03,B02', true, 'EPSG:4326', false);

