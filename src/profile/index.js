export default function createProfileHandlers({
    db,
    getUserById,
    updateUser,
    deleteUser,
    logger = console,
}) {
    return {
        getProfile: async (req, res, next) => {
            try {
                let token = req.params.id;
                if (!token) {
                    if (!req.payload) throw new Error("Invalid request")
                    token = req.payload.aud;
                    if (!token) {
                        throw new Error("Invalid request")
                    }
                }

                const user = await getUserById(token);
                if (!user) return res.status(404).send("User not found");
                delete user.password;
                res.send({ user });
            } catch (err) {
                logger.error("getProfile error:", err);
                next(err.message);
            }
        },

        updateProfile: async (req, res, next) => {
            try {
                await updateUser(req.payload.aud, req.body);
                res.send({ message: "Profile updated" });
            } catch (err) {
                logger.error("updateProfile error:", err);
                next(err.message);
            }
        },

        deleteProfile: async (req, res, next) => {
            try {
                await deleteUser(req.payload.aud);
                res.send({ message: "Profile deleted" });
            } catch (err) {
                logger.error("deleteProfile error:", err);
                next(err.message);
            }
        }
    };
}
