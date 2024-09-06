const { Activity } = require("../../models/activity");
const { v4: uuidv4 } = require("uuid");

const addActivity = async (id, body) => {
    try {
        const addActvty = await Activity.create({
            _id: uuidv4(),
            userId: id,
            body: body
        });
        console.log("activity", addActvty);
    } catch (error) {
        console.error(error);
        // throw new Error(error);
        
    }
};

const getActivity = async (id, pageNumber) => {
    try {
        let page = parseInt(pageNumber) || 1;
        let limit = parseInt(query.limit) || 10;
        const listCount = await Activity.countDocuments({userId: id});
        if (!listCount) return null;
        let pages = Math.ceil(listCount / limit);
        let skip = limit * (page - 1) || 0;
        const fetchActivity = await Activity.find({userId: id})
        .limit(limit)
        .skip(skip);
        if (!fetchActivity) return null;
        let response ={
            page,
            pages,
            skip,
            activities: fetchActivity
          };
        return response;
    } catch (error) {
        throw new Error(error);
        
    }
};

module.exports = {
    addActivity,
    getActivity
}