import {dangerousPropertyRegex} from '../utils';

export default function(instance) {
  instance.registerHelper('lookup', function(obj, field) {
    if (!obj) {
      return obj;
    }
    if (dangerousPropertyRegex.test(String(field)) && !Object.prototype.propertyIsEnumerable.call(obj, field)) {
      return undefined;
    }
    return obj[field];
  });
}
