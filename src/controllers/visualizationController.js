const Website = require("../models/Website");
const { getVisualizationDashboard } = require("../services/visualizationService");

exports.getDashboard = async (req, res) => {
  try {
    const query = { userId: req.user.id };

    if (req.query.websiteId) {
      query._id = req.query.websiteId;
    }

    const website = await Website.findOne(query).select("_id userId").lean();

    if (!website) {
      return res.status(404).json({ msg: "Website not found" });
    }

    const dashboard = await getVisualizationDashboard({
      userId: website.userId,
      websiteId: website._id,
      range: req.query.range,
      limit: req.query.limit
    });

    res.json(dashboard);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};
