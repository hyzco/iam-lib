import Joi from 'joi';

export const authSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  name: Joi.string().optional(),
  surname: Joi.string().optional(),
  ext: Joi.string().optional(),
  phone: Joi.string().optional(),
});
