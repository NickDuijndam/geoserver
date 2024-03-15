/*! @maps4html/web-map-custom-element 15-03-2024 */

class MapFeature extends HTMLElement{static get observedAttributes(){return["zoom","min","max"]}#hasConnected;get zoom(){let t={},e=this.getMeta("zoom");return e&&(t=M._metaContentToObject(e.getAttribute("content"))),"MAP-LINK"===this._parentEl.nodeName?+(this.hasAttribute("zoom")?this.getAttribute("zoom"):t.value||t.max||this._initialZoom):+(this.hasAttribute("zoom")?this.getAttribute("zoom"):this._initialZoom)}set zoom(t){t=parseInt(t,10);!isNaN(t)&&t>=this.min&&t<=this.max&&this.setAttribute("zoom",t)}get min(){let t={},e=this.getMeta("zoom");e&&(t=M._metaContentToObject(e.getAttribute("content")));return"MAP-LINK"===this._parentEl.nodeName?+(this.hasAttribute("min")?this.getAttribute("min"):t.min||this._parentEl.getZoomBounds().minZoom):+(this.hasAttribute("min")?this.getAttribute("min"):t.min||0)}set min(t){var e=parseInt(t,10),t=this.getLayerEl().extent.zoom;isNaN(e)||(e>=t.minZoom&&e<=t.maxZoom?this.setAttribute("min",e):this.setAttribute("min",t.minZoom))}get max(){let t={},e=this.getMeta("zoom");e&&(t=M._metaContentToObject(e.getAttribute("content")));var o=this.getMapEl()._map.options.crs.options.resolutions.length-1;return"MAP-LINK"===this._parentEl.nodeName?+(this.hasAttribute("max")?this.getAttribute("max"):t.max||this._parentEl.getZoomBounds().maxZoom):+(this.hasAttribute("max")?this.getAttribute("max"):t.max||o)}set max(t){var e=parseInt(t,10),t=this.getLayerEl().extent.zoom;isNaN(e)||(e>=t.minZoom&&e<=t.maxZoom?this.setAttribute("max",e):this.setAttribute("max",t.maxZoom))}get extent(){if(this.isConnected)return this._getFeatureExtent||(this._getFeatureExtent=this._memoizeExtent()),this._getFeatureExtent()}getLayerEl(){let t;return t=this.getRootNode()instanceof ShadowRoot?this.getRootNode().host.getRootNode()instanceof ShadowRoot?this.getRootNode().host.getRootNode().host:"MAP-LINK"===this.getRootNode().host.nodeName?this.getRootNode().host.closest("layer-"):this.getRootNode().host:this.closest("layer-"),t}getMapEl(){return this.getLayerEl().closest("mapml-viewer,map[is=web-map]")}attributeChangedCallback(t,e,o){if(this.#hasConnected)switch(t){case"min":case"max":case"zoom":e!==o&&this.reRender(this._featureLayer)}}constructor(){super()}connectedCallback(){this.#hasConnected=!0,this._initialZoom=this.getMapEl().zoom,this._parentEl="LAYER-"===this.parentNode.nodeName.toUpperCase()||"MAP-LINK"===this.parentNode.nodeName.toUpperCase()?this.parentNode:this.parentNode.host,this.getLayerEl().hasAttribute("data-moving")||this._parentEl.parentElement?.hasAttribute("data-moving")||(this._observer=new MutationObserver(t=>{for(var e of t){if("attributes"===e.type&&e.target===this)return;this.reRender(this._featureLayer)}}),this._observer.observe(this,{childList:!0,subtree:!0,attributes:!0,attributeOldValue:!0,characterData:!0}))}disconnectedCallback(){this.getLayerEl()?.hasAttribute("data-moving")||this._parentEl.parentElement?.hasAttribute("data-moving")||(this._observer.disconnect(),this._featureLayer&&this.removeFeature(this._featureLayer))}reRender(e){if(this._groupEl.isConnected){var o=this._getFallbackCS();let t=document.createElement("span");this._groupEl.insertAdjacentElement("beforebegin",t),e._staticFeature&&e._removeFromFeaturesList(this._geometry),e.removeLayer(this._geometry),this._geometry=e.createGeometry(this,o).addTo(e),t.replaceWith(this._geometry.options.group),e._validateRendering(),delete this._getFeatureExtent,this._setUpEvents()}}removeFeature(t){t.removeLayer(this._geometry),t._staticFeature&&t._removeFromFeaturesList(this._geometry),t.options.properties=null,delete this._geometry,this._getFeatureExtent&&delete this._getFeatureExtent}addFeature(t){this._featureLayer=t;var e,o=this.getLayerEl();this.querySelector("map-geometry")&&(e=this._getFallbackCS(),o.src&&o.shadowRoot,this._geometry=t.createGeometry(this,e),t.addLayer(this._geometry),this._setUpEvents())}_setUpEvents(){["click","focus","blur","keyup","keydown"].forEach(o=>{this._groupEl.addEventListener(o,e=>{if("click"===o){let t=new PointerEvent(o,{cancelable:!0});t.originalEvent=e,this.dispatchEvent(t)}else if("keyup"===o||"keydown"===o){let t=new KeyboardEvent(o,{cancelable:!0});t.originalEvent=e,this.dispatchEvent(t)}else{let t=new FocusEvent(o,{cancelable:!0});t.originalEvent=e,this.dispatchEvent(t)}})})}_getFallbackCS(){let e;if("MAP-LINK"===this._parentEl.nodeName)e=this._parentEl.shadowRoot.querySelector("map-meta[name=cs]")||this._parentEl.parentElement.getMeta("cs");else{let t=this.getLayerEl();e=(t.src?t.shadowRoot:t).querySelector("map-meta[name=cs]")}return e&&M._metaContentToObject(e.getAttribute("content")).content||"gcrs"}_memoizeExtent(){let p;return function(){if(p&&this._getFeatureExtent)return p;{let r=this.getMapEl()._map,t=this.querySelector("map-geometry"),e=t.getAttribute("cs")||this._getFallbackCS(),o=this.zoom,i=t.querySelectorAll("map-point, map-linestring, map-polygon, map-multipoint, map-multilinestring"),s=[1/0,1/0,Number.NEGATIVE_INFINITY,Number.NEGATIVE_INFINITY];for(var n of i){var m=n.querySelectorAll("map-coordinates");for(let t=0;t<m.length;++t)s=function(t,e,o){var i=e.innerHTML.trim().replace(/<[^>]+>/g,"").replace(/\s+/g," ").split(/[<>\ ]/g);switch(t.tagName.toUpperCase()){case"MAP-POINT":o=M._updateExtent(o,+i[0],+i[1]);break;case"MAP-LINESTRING":case"MAP-POLYGON":case"MAP-MULTIPOINT":case"MAP-MULTILINESTRING":for(let t=0;t<i.length;t+=2)o=M._updateExtent(o,+i[t],+i[t+1])}return o}(n,m[t],s)}var l=L.point(s[0],s[1]),h=L.point(s[2],s[3]);let a=M.boundsToPCRSBounds(L.bounds(l,h),o,r.options.projection,e);if(1===i.length&&"MAP-POINT"===i[0].tagName.toUpperCase()){let t=r.options.projection,e=this.hasAttribute("max")?+this.getAttribute("max"):M[t].options.resolutions.length-1,o=M[t].options.crs.tile.bounds.getCenter(),i=M[t].transformation.transform(a.min,M[t].scale(+this.zoom||e));a=M.pixelToPCRSBounds(L.bounds(i.subtract(o),i.add(o)),this.zoom||e,t)}h=Object.assign(M._convertAndFormatPCRS(a,r.options.crs,r.options.projection),{zoom:this._getZoomBounds()});return p=h}}}_getZoomBounds(){return{minZoom:this.min,maxZoom:this.max,minNativeZoom:this.zoom,maxNativeZoom:this.zoom}}getZoomToZoom(){var t=this.extent.topLeft.pcrs,e=this.extent.bottomRight.pcrs,o=L.bounds(L.point(t.horizontal,t.vertical),L.point(e.horizontal,e.vertical)),i=this.getMapEl()._map.options.projection,t=this.getLayerEl().extent.zoom,e=t.minZoom||0,i=t.maxZoom||M[i].options.resolutions.length-1;let r;return this.hasAttribute("zoom")?r=this.zoom:(r=M.getMaxZoom(o,this.getMapEl()._map,e,i),this.max<r?r=this.max:this.min>r&&(r=this.min)),r<e?r=e:r>i&&(r=i),r}getMeta(t){var e=t.toLowerCase();if("cs"===e||"zoom"===e||"projection"===e){var o=this._parentEl.shadowRoot.querySelector(`map-meta[name=${e}][content]`);return"MAP-LINK"===this._parentEl.nodeName?o||this._parentEl.parentElement.getMeta(t):(this._parentEl.src?this._parentEl.shadowRoot:this._parentEl).querySelector(`map-meta[name=${e}][content]`)}}mapml2geojson(t){t=Object.assign({},{propertyFunction:null,transform:!0},t);let e={type:"Feature",properties:{},geometry:{}},o=this.querySelector("map-properties");o?"function"==typeof t.propertyFunction?e.properties=t.propertyFunction(o):o.querySelector("table")?(n=o.querySelector("table").cloneNode(!0),e.properties=M._table2properties(n)):e.properties={prop0:o.innerHTML.replace(/(<([^>]+)>)/gi,"").replace(/\s/g,"")}:e.properties=null;let i=null,r=null,s=this.getMapEl()._map;t.transform&&(i=new proj4.Proj(s.options.crs.code),r=new proj4.Proj("EPSG:4326"),"EPSG:3857"!==s.options.crs.code&&"EPSG:4326"!==s.options.crs.code||(t.transform=!1));var a=this.querySelector("map-geometry").querySelector("map-geometrycollection"),n=this.querySelector("map-geometry").querySelectorAll("map-point, map-polygon, map-linestring, map-multipoint, map-multipolygon, map-multilinestring");if(a){e.geometry.type="GeometryCollection",e.geometry.geometries=[];for(var m of n)e.geometry.geometries.push(M._geometry2geojson(m,i,r,t.transform))}else e.geometry=M._geometry2geojson(n[0],i,r,t.transform);return e}click(){let t=this._groupEl,e=t.getBoundingClientRect();var o=new MouseEvent("click",{clientX:e.x+e.width/2,clientY:e.y+e.height/2,button:0}),i=this.querySelector("map-properties");if("link"===t.getAttribute("role"))for(var r of t.children)r.mousedown.call(this._geometry,o),r.mouseup.call(this._geometry,o);let s=new PointerEvent("click",{cancelable:!0});if(s.originalEvent=o,this.dispatchEvent(s),i&&this.isConnected){let t=this._geometry,e=t._layers;for(var a in e)e[a].isPopupOpen()&&e[a].closePopup();t.isPopupOpen()?t.closePopup():s.originalEvent.cancelBubble||t.openPopup()}}focus(t){this._groupEl.focus(t)}blur(){document.activeElement.shadowRoot?.activeElement!==this._groupEl&&document.activeElement.shadowRoot?.activeElement.parentNode!==this._groupEl||(this._groupEl.blur(),this.getMapEl()._map.getContainer().focus())}zoomTo(){let t=this.extent,e=this.getMapEl()._map,o=t.topLeft.pcrs,i=t.bottomRight.pcrs,r=L.bounds(L.point(o.horizontal,o.vertical),L.point(i.horizontal,i.vertical)),s=e.options.crs.unproject(r.getCenter(!0));e.setView(s,this.getZoomToZoom(),{animate:!1})}whenReady(){return new Promise((e,t)=>{let o,i;this.isConnected?e():(o=setInterval(function(t){t.isConnected&&(clearInterval(o),clearTimeout(i),e())},200,this),i=setTimeout(function(){clearInterval(o),clearTimeout(i),t("Timeout reached waiting for feature to be ready")},5e3))})}}export{MapFeature};
//# sourceMappingURL=map-feature.js.map