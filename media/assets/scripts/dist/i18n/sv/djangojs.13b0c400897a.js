(function(e){var t=e.django||(e.django={});t.pluralidx=function(e){return e==1?0:1},t.gettext=function(e){return e},t.ngettext=function(e,t,n){return n==1?e:t},t.gettext_noop=function(e){return e},t.pgettext=function(e,t){return t},t.npgettext=function(e,t,n,r){return r==1?t:n},t.interpolate=function(e,t,n){return n?e.replace(/%\(\w+\)s/g,function(e){return String(t[e.slice(2,-2)])}):e.replace(/%s/g,function(e){return String(t.shift())})},t.formats={DATETIME_FORMAT:"j F Y H:i",DATETIME_INPUT_FORMATS:["%Y-%m-%d %H:%M:%S","%Y-%m-%d %H:%M","%Y-%m-%d","%m/%d/%Y %H:%M:%S","%m/%d/%Y %H:%M","%m/%d/%Y","%m/%d/%y %H:%M:%S","%m/%d/%y %H:%M","%m/%d/%y","%Y-%m-%d %H:%M:%S.%f"],DATE_FORMAT:"j F Y",DATE_INPUT_FORMATS:["%Y-%m-%d","%m/%d/%Y","%m/%d/%y"],DECIMAL_SEPARATOR:",",FIRST_DAY_OF_WEEK:"1",MONTH_DAY_FORMAT:"j F",NUMBER_GROUPING:"3",SHORT_DATETIME_FORMAT:"Y-m-d H:i",SHORT_DATE_FORMAT:"Y-m-d",THOUSAND_SEPARATOR:" ",TIME_FORMAT:"H:i",TIME_INPUT_FORMATS:["%H:%M:%S","%H:%M"],YEAR_MONTH_FORMAT:"F Y"},t.get_format=function(e){var n=t.formats[e];return typeof n=="undefined"?e:n},e.pluralidx=t.pluralidx,e.gettext=t.gettext,e.ngettext=t.ngettext,e.gettext_noop=t.gettext_noop,e.pgettext=t.pgettext,e.npgettext=t.npgettext,e.interpolate=t.interpolate,e.get_format=t.get_format})(this);