import createError from 'http-errors';
import bcrypt from 'bcrypt';

export default function changePwHandler({ db, userRepo, logger, audit }) {
  return async (req, res, next) => {
    try {
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: "Current and new passwords are required." });
      }

      const userId = req.payload?.aud;
      const user = await userRepo.getById(userId);
      if (!user) {
        throw createError.NotFound('User not found');
      }
      logger.log("CURRENT PW =", currentPassword);
      logger.log("user password = ", user.password)
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Current password is incorrect." });
      }

      const hashed = await bcrypt.hash(newPassword, 10);

      await db('users')
        .where({ id: userId })
        .update({ password: hashed });

      audit({ action: 'user.pw.change', userId, status: "success" });

      return res.status(200).json({ message: "Password changed successfully." });
    } catch (err) {
      if (err.isJoi) err.status = 422;
      audit({ action: 'user.pw.change', userId: req.payload?.aud, status: "fail" });
      next(err);
    }
  };
}
